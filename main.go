package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// API Constants
const (
	// SSL Labs API base URL
	apiBaseURL = "https://api.ssllabs.com/api/v2"
	
	// API Endpoints
	analyzeEndpoint = "/analyze"
)

// Constantes para estados de evaluación
const (
	statusDNS         = "DNS"
	statusInProgress  = "IN_PROGRESS"
	statusReady       = "READY"
	statusError       = "ERROR"
)

// Host represents the main response from the /analyze endpoint
type Host struct {
	Host           string     `json:"host"`
	Port           int        `json:"port"`
	Protocol       string     `json:"protocol"`
	IsPublic       bool       `json:"isPublic"`
	Status         string     `json:"status"`         // DNS, IN_PROGRESS, READY, ERROR
	StatusMessage  string     `json:"statusMessage"`  // Mensaje de estado o error
	StartTime      int64      `json:"startTime"`      // Timestamp de inicio
	TestTime       int64      `json:"testTime"`       // Timestamp de finalización
	EngineVersion  string     `json:"engineVersion"`
	CriteriaVersion string    `json:"criteriaVersion"`
	Endpoints      []Endpoint `json:"endpoints"`      // Lista de endpoints evaluados
}

// Endpoint represents information about a single endpoint (server)
type Endpoint struct {
	IPAddress      string          `json:"ipAddress"`      // IP del endpoint
	ServerName     string          `json:"serverName"`     // Nombre del servidor (reverse DNS)
	StatusMessage  string          `json:"statusMessage"`  // "Ready" si la evaluación fue exitosa
	StatusDetails  string          `json:"statusDetails"`
	Grade          string          `json:"grade"`          // Calificación: A+, A, A-, B, C, D, E, F, T, M
	GradeTrustIgnored string       `json:"gradeTrustIgnored"`
	HasWarnings    bool            `json:"hasWarnings"`
	Progress       int             `json:"progress"`       // 0-100, -1 si no ha empezado
	Duration       int             `json:"duration"`       // Duración en milisegundos
	ETA            int             `json:"eta"`            // Tiempo estimado hasta completar (segundos)
	Details        *EndpointDetails `json:"details,omitempty"` // Solo presente cuando all=done y status=READY
}

// EndpointDetails contains complete assessment information for an endpoint
type EndpointDetails struct {
	Protocols []Protocol `json:"protocols"`      // Protocolos TLS soportados
	Cert      *Cert      `json:"cert,omitempty"` // Información del certificado
}

// Protocol represents a TLS/SSL protocol version
type Protocol struct {
	Name    string `json:"name"`    // "TLS" o "SSL"
	Version string `json:"version"` // "1.2", "1.3", etc.
	Q       *int   `json:"q"`       // 0 si es inseguro, null si es seguro
}

// Cert represents certificate information
type Cert struct {
	IssuerLabel string `json:"issuerLabel"` // Nombre del emisor (ej: "Let's Encrypt")
	NotBefore   int64  `json:"notBefore"`   // Timestamp: válido desde
	NotAfter    int64  `json:"notAfter"`    // Timestamp: válido hasta
}

// ErrorResponse represents an error response from the API
type ErrorResponse struct {
	Errors []APIError `json:"errors"`
}

// APIError represents a single error from the API
type APIError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// validateDomain performs basic validation on the domain input
func validateDomain(domain string) error {
	// Remover espacios en blanco
	domain = strings.TrimSpace(domain)

	if domain == "" {
		return fmt.Errorf("el dominio no puede estar vacío")
	}
	
	// Validación básica: debe tener al menos un punto (para ser un dominio válido)
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("el dominio debe tener un formato válido (ej: example.com)")
	}
	
	return nil
}

// buildAnalyzeURL constructs the URL for the /analyze endpoint with the given parameters
// Parameters:
//   - host: domain to evaluate (required)
//   - publish: "on" to publish results, "off" (default) to keep private
//   - startNew: "on" to start new assessment (only on first call), omit on subsequent calls
//   - all: "done" to get full information when ready
func buildAnalyzeURL(host string, publish bool, startNew bool, allDone bool) string {
	url := fmt.Sprintf("%s%s?host=%s", apiBaseURL, analyzeEndpoint, host)
	
	if publish {
		url += "&publish=on"
	} else {
		url += "&publish=off"
	}
	
	if startNew {
		url += "&startNew=on"
	}
	
	if allDone {
		url += "&all=done"
	}
	
	return url
}

// HTTPClient wraps HTTP operations for SSL Labs API
type HTTPClient struct {
	client *http.Client
}

// NewHTTPClient creates a new HTTP client with timeout
func NewHTTPClient() *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Get performs a GET request to the SSL Labs API
// Returns the response body and handles HTTP status codes
func (c *HTTPClient) Get(url string) ([]byte, error) {
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error de conexión: %w", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error leyendo respuesta: %w", err)
	}
	
	// Manejo de códigos HTTP esenciales
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusBadRequest:
		// Intentar parsear error de la API
		var apiErr ErrorResponse
		if json.Unmarshal(body, &apiErr) == nil && len(apiErr.Errors) > 0 {
			return nil, fmt.Errorf("error de la API (400): %s - %s", 
				apiErr.Errors[0].Field, apiErr.Errors[0].Message)
		}
		return nil, fmt.Errorf("error de invocación (400): parámetros inválidos")
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("rate limit excedido (429): por favor espera antes de reintentar")
	case http.StatusInternalServerError:
		return nil, fmt.Errorf("error interno del servidor (500): por favor intenta más tarde")
	case http.StatusServiceUnavailable:
		return nil, fmt.Errorf("servicio no disponible (503): por favor intenta más tarde")
	case 529: // Service overloaded
		return nil, fmt.Errorf("servicio sobrecargado (529): por favor intenta más tarde")
	default:
		return nil, fmt.Errorf("código HTTP inesperado: %d", resp.StatusCode)
	}
}

// Analyze initiates or checks the status of an SSL assessment
func (c *HTTPClient) Analyze(host string, publish bool, startNew bool, allDone bool) (*Host, error) {
	url := buildAnalyzeURL(host, publish, startNew, allDone)
	
	body, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	
	var hostResp Host
	if err := json.Unmarshal(body, &hostResp); err != nil {
		return nil, fmt.Errorf("error parseando respuesta JSON: %w", err)
	}
	
	return &hostResp, nil
}

// PollAssessment performs polling until the assessment is complete
// Uses variable polling intervals as recommended by SSL Labs:
// - 5 seconds until status becomes IN_PROGRESS
// - 10 seconds after IN_PROGRESS until completion
func PollAssessment(client *HTTPClient, domain string, maxTimeout time.Duration) (*Host, error) {
	startTime := time.Now()
	isFirstCall := true
	
	// Primera llamada con startNew=on
	host, err := client.Analyze(domain, false, true, true)
	if err != nil {
		return nil, err
	}
	
	// Mostrar estado inicial
	showProgress(host, isFirstCall)
	isFirstCall = false
	
	// Ciclo de polling
	for {
		// Verificar timeout
		if time.Since(startTime) > maxTimeout {
			return nil, fmt.Errorf("timeout: la evaluación tomó más de %v", maxTimeout)
		}
		
		// Verificar si está completo o hay error
		if host.Status == statusReady {
			return host, nil
		}
		if host.Status == statusError {
			return nil, fmt.Errorf("error en la evaluación: %s", host.StatusMessage)
		}
		
		// Verificar si todos los endpoints están listos (statusMessage == "Ready")
		// Si todos están Ready, podemos procesar los que tengan details disponibles
		if len(host.Endpoints) > 0 {
			endpointsWithProgress := 0
			endpointsReady := 0
			endpointsWithDetails := 0
			
			for _, endpoint := range host.Endpoints {
				// Solo contar endpoints que han iniciado (progress >= 0)
				if endpoint.Progress >= 0 {
					endpointsWithProgress++
					
					if endpoint.StatusMessage == "Ready" {
						endpointsReady++
						
						if endpoint.Details != nil {
							endpointsWithDetails++
						}
					}
				}
			}
			
			// Si todos los endpoints están Ready y todos tienen details, está completo
			if endpointsWithProgress > 0 && 
			   endpointsReady == endpointsWithProgress && 
			   endpointsWithDetails == endpointsWithProgress {
				return host, nil
			}
			
			// Si todos están Ready pero algunos no tienen details, esperar un poco más
			if endpointsWithProgress > 0 && endpointsReady == endpointsWithProgress {
				// Si todos tienen details, retornar inmediatamente
				if endpointsWithDetails == endpointsWithProgress {
					return host, nil
				}
				// Si algunos tienen details, esperar un poco más y retornar
				if endpointsWithDetails > 0 {
					time.Sleep(10 * time.Second)
					host, err = client.Analyze(domain, false, false, true)
					if err != nil {
						return nil, err
					}
					// Retornar (ProcessResults procesará solo los que tienen details)
					return host, nil
				}
				// Si ninguno tiene details, continuar con el polling normal
				// (no retornar todavía, esperar a que lleguen los details)
			}
		}
		
		// Determinar intervalo de espera según el estado (polling variable)
		var sleepDuration time.Duration
		if host.Status == statusDNS {
			sleepDuration = 5 * time.Second
		} else if host.Status == statusInProgress {
			sleepDuration = 10 * time.Second
		} else {
			sleepDuration = 5 * time.Second
		}
		
		// Esperar antes de la siguiente consulta
		time.Sleep(sleepDuration)
		
		// Consultar estado nuevamente (SIN startNew, solo en la primera llamada)
		host, err = client.Analyze(domain, false, false, true)
		if err != nil {
			return nil, err
		}
		
		// Mostrar progreso
		showProgress(host, isFirstCall)
	}
}

// showProgress displays progress information to the user
func showProgress(host *Host, isFirstCall bool) {
	switch host.Status {
	case statusDNS:
		fmt.Println("Resolviendo DNS...")
	case statusInProgress:
		// Mostrar progreso si está disponible en los endpoints
		if len(host.Endpoints) > 0 && host.Endpoints[0].Progress >= 0 {
			progress := host.Endpoints[0].Progress
			if progress == 100 {
				// Si está en 100%, verificar el estado de todos los endpoints
				endpointsReady := 0
				endpointsWithDetails := 0
				totalEndpoints := 0
				for _, endpoint := range host.Endpoints {
					if endpoint.Progress >= 0 {
						totalEndpoints++
						if endpoint.StatusMessage == "Ready" {
							endpointsReady++
							if endpoint.Details != nil {
								endpointsWithDetails++
							}
						}
					}
				}
				
				if endpointsReady > 0 {
					if endpointsWithDetails < endpointsReady {
						// Algunos endpoints están listos pero esperando detalles
						if endpointsWithDetails > 0 {
							fmt.Printf("Esperando detalles de seguridad TLS... (%d/%d endpoints con detalles completos)\n", 
								endpointsWithDetails, endpointsReady)
						} else {
							fmt.Printf("Esperando detalles de seguridad TLS... (%d endpoints listos, esperando detalles)\n", 
								endpointsReady)
						}
					} else {
						// Todos los endpoints Ready tienen details
						fmt.Println("Finalizando evaluación...")
					}
				} else {
					// En 100% pero aún no todos están listos
					fmt.Printf("Esperando que finalice la evaluación... (%d endpoints en progreso)\n", totalEndpoints)
				}
			} else {
				fmt.Printf("Evaluando seguridad TLS... (%d%%)\n", progress)
			}
		} else {
			fmt.Println("Evaluando seguridad TLS...")
		}
	case statusReady:
		fmt.Println("Evaluación completada.")
	case statusError:
		// El error se manejará en el polling
	default:
		if isFirstCall {
			fmt.Println("Iniciando evaluación...")
		}
	}
}

// AssessmentResult contiene la información procesada de seguridad TLS
type AssessmentResult struct {
	Domain          string
	Endpoints       []EndpointResult
	OverallGrade    string // El peor grade si hay múltiples endpoints
}

// EndpointResult contiene la información de seguridad TLS de un endpoint
type EndpointResult struct {
	IPAddress      string
	Grade          string
	TLSProtocols   []string
	CertIssuer     string
	CertValidFrom  int64
	CertValidTo    int64
}

// compareGrades compara dos grades y retorna -1 si grade1 es peor, 0 si son iguales, 1 si grade1 es mejor
// Orden: A+ > A > A- > B+ > B > B- > C+ > C > C- > D+ > D > D- > E > F > T > M
func compareGrades(grade1, grade2 string) int {
	gradeOrder := map[string]int{
		"A+": 15, "A": 14, "A-": 13,
		"B+": 12, "B": 11, "B-": 10,
		"C+": 9, "C": 8, "C-": 7,
		"D+": 6, "D": 5, "D-": 4,
		"E": 3, "F": 2, "T": 1, "M": 0,
	}
	
	score1, ok1 := gradeOrder[grade1]
	score2, ok2 := gradeOrder[grade2]
	
	// Si algún grade no está en el mapa, usar comparación alfabética inversa como fallback
	if !ok1 || !ok2 {
		if grade1 < grade2 {
			return -1 // grade1 es peor (alfabéticamente menor, ej: "A" < "F")
		}
		if grade1 > grade2 {
			return 1
		}
		return 0
	}
	
	if score1 < score2 {
		return -1 // grade1 es peor
	}
	if score1 > score2 {
		return 1 // grade1 es mejor
	}
	return 0
}

// findWorstGrade encuentra el peor grade de una lista de grades
func findWorstGrade(grades []string) string {
	if len(grades) == 0 {
		return ""
	}
	
	worst := grades[0]
	for i := 1; i < len(grades); i++ {
		if compareGrades(grades[i], worst) < 0 {
			worst = grades[i]
		}
	}
	return worst
}

// ProcessResults extrae y procesa la información de seguridad TLS del host
func ProcessResults(host *Host) (*AssessmentResult, error) {
	// No requerimos que el status sea READY porque podemos procesar endpoints
	// que ya tienen statusMessage "Ready", incluso si el status general es IN_PROGRESS
	
	if len(host.Endpoints) == 0 {
		return nil, fmt.Errorf("no hay endpoints disponibles en la respuesta")
	}
	
	result := &AssessmentResult{
		Domain:    host.Host,
		Endpoints: []EndpointResult{},
	}
	
	var allGrades []string
	
	// Procesar cada endpoint
	for _, endpoint := range host.Endpoints {
		// Solo procesar endpoints que estén listos
		if endpoint.StatusMessage != "Ready" {
			continue
		}
		
		// Verificar que details esté presente
		if endpoint.Details == nil {
			continue
		}
		
		endpointResult := EndpointResult{
			IPAddress: endpoint.IPAddress,
			Grade:     endpoint.Grade,
		}
		
		// Extraer protocolos TLS (Q == nil significa seguro, Q == 0 significa inseguro)
		for _, protocol := range endpoint.Details.Protocols {
			if protocol.Q == nil { // Q == null significa que el protocolo es seguro
				protocolName := fmt.Sprintf("%s %s", protocol.Name, protocol.Version)
				endpointResult.TLSProtocols = append(endpointResult.TLSProtocols, protocolName)
			}
		}
		
		// Extraer información del certificado
		if endpoint.Details.Cert != nil {
			endpointResult.CertIssuer = endpoint.Details.Cert.IssuerLabel
			endpointResult.CertValidFrom = endpoint.Details.Cert.NotBefore
			endpointResult.CertValidTo = endpoint.Details.Cert.NotAfter
		}
		
		result.Endpoints = append(result.Endpoints, endpointResult)
		allGrades = append(allGrades, endpoint.Grade)
	}
	
	if len(result.Endpoints) == 0 {
		// Si no hay endpoints con details, puede que aún no estén listos
		return nil, fmt.Errorf("no hay endpoints listos con información completa. Status: %s", host.Status)
	}
	
	// Calcular el peor grade (overall grade)
	result.OverallGrade = findWorstGrade(allGrades)
	
	return result, nil
}

func main() {
	// Punto 3: Validación de entrada CLI
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Error: dominio requerido\n")
		fmt.Fprintf(os.Stderr, "Usage: %s <domain>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Ejemplo: %s google.com\n", os.Args[0])
		os.Exit(1)
	}
	
	domain := strings.TrimSpace(os.Args[1])
	
	// Validar dominio
	if err := validateDomain(domain); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		fmt.Fprintf(os.Stderr, "Usage: %s <domain>\n", os.Args[0])
		os.Exit(1)
	}
	
	fmt.Printf("SSL Labs Scanner - Verificando seguridad TLS de: %s\n\n", domain)
	
	// Punto 4: Cliente HTTP
	client := NewHTTPClient()
	
	// Punto 6: Lógica de polling
	maxTimeout := 10 * time.Minute
	host, err := PollAssessment(client, domain, maxTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
	
	// La evaluación está completa (status == READY)
	fmt.Printf("\n✅ Evaluación completada\n")
	
	// Punto 7: Procesar resultados
	result, err := ProcessResults(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error procesando resultados: %s\n", err)
		os.Exit(1)
	}
	
	// Punto 8: Mostrar resultados
	DisplayResults(result)
}

// DisplayResults muestra los resultados de seguridad TLS de forma clara
func DisplayResults(result *AssessmentResult) {
	fmt.Printf("\n=== Resultados de Seguridad TLS ===\n")
	fmt.Printf("Dominio: %s\n", result.Domain)
	fmt.Printf("Grade General: %s\n\n", result.OverallGrade)
	
	// Mostrar información de cada endpoint
	for i, endpoint := range result.Endpoints {
		fmt.Printf("--- Endpoint %d: %s ---\n", i+1, endpoint.IPAddress)
		fmt.Printf("Grade: %s\n", endpoint.Grade)
		
		// Protocolos TLS
		if len(endpoint.TLSProtocols) > 0 {
			fmt.Printf("Protocolos TLS: %s\n", strings.Join(endpoint.TLSProtocols, ", "))
		} else {
			fmt.Printf("Protocolos TLS: No hay protocolos seguros disponibles\n")
		}
		
		// Información del certificado
		if endpoint.CertIssuer != "" {
			fmt.Printf("Certificado Emisor: %s\n", endpoint.CertIssuer)
		}
		
		if endpoint.CertValidFrom > 0 && endpoint.CertValidTo > 0 {
			validFrom := time.Unix(endpoint.CertValidFrom/1000, 0)
			validTo := time.Unix(endpoint.CertValidTo/1000, 0)
			fmt.Printf("Certificado Válido: %s hasta %s\n", 
				validFrom.Format("2006-01-02"), 
				validTo.Format("2006-01-02"))
		}
		
		fmt.Println()
	}
	
	if len(result.Endpoints) > 1 {
		fmt.Printf("=== Resumen ===\n")
		fmt.Printf("Grade General (peor de todos los endpoints): %s\n", result.OverallGrade)
	}
}
