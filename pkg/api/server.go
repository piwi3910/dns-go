// Package api provides the REST API server for the DNS server management GUI.
package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/piwi3910/dns-go/pkg/api/types"
	"github.com/piwi3910/dns-go/pkg/bridge"
	"github.com/piwi3910/dns-go/pkg/config"
	"github.com/piwi3910/dns-go/web"
)

const (
	cookieName     = "dns_session"
	defaultPassword = "admin"
)

// Server is the API server for the DNS management GUI.
type Server struct {
	config       *config.Config
	dnsService   bridge.DNSService
	jwtSecret    []byte
	passwordHash string
	startTime    time.Time
	httpServer   *http.Server

	// SSE broadcaster
	sseClients    map[chan []byte]bool
	sseRegister   chan chan []byte
	sseUnregister chan chan []byte
	sseMu         sync.RWMutex
}

// NewServer creates a new API server.
func NewServer(cfg *config.Config, dnsService bridge.DNSService) *Server {
	s := &Server{
		config:        cfg,
		dnsService:    dnsService,
		startTime:     time.Now(),
		sseClients:    make(map[chan []byte]bool),
		sseRegister:   make(chan chan []byte),
		sseUnregister: make(chan chan []byte),
	}

	// Setup JWT secret
	if cfg.API.Auth.JWTSecret != "" {
		s.jwtSecret = []byte(cfg.API.Auth.JWTSecret)
	} else {
		// Generate random secret
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			log.Printf("Warning: failed to generate random JWT secret: %v", err)
			s.jwtSecret = []byte("default-insecure-secret-change-me")
		} else {
			s.jwtSecret = secret
		}
	}

	// Setup password hash
	if cfg.API.Auth.PasswordHash != "" {
		s.passwordHash = cfg.API.Auth.PasswordHash
	} else {
		// Hash default password
		hash, err := bcrypt.GenerateFromPassword([]byte(defaultPassword), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Warning: failed to hash default password: %v", err)
			s.passwordHash = ""
		} else {
			s.passwordHash = string(hash)
			log.Printf("API: Using default admin password. Change it in production!")
		}
	}

	return s
}

// Start starts the API server.
func (s *Server) Start() error {
	r := s.setupRouter()

	// Start SSE broadcaster
	go s.runSSEBroadcaster()

	s.httpServer = &http.Server{
		Addr:              s.config.API.ListenAddress,
		Handler:           r,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second, // Longer for SSE
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("API server starting on %s", s.config.API.ListenAddress)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the API server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

func (s *Server) setupRouter() chi.Router {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// CORS
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   s.config.API.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health check (no auth required)
	r.Get("/api/health", s.handleHealth)

	// Auth routes (no auth required)
	r.Post("/api/auth/login", s.handleLogin)
	r.Post("/api/auth/logout", s.handleLogout)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(s.authMiddleware)

		r.Get("/api/auth/me", s.handleMe)
		r.Get("/api/stats", s.handleGetStats)
		r.Get("/api/stats/stream", s.handleStatsSSE)
		r.Get("/api/upstreams", s.handleGetUpstreams)
		r.Put("/api/upstreams", s.handleUpdateUpstreams)
		r.Get("/api/zones", s.handleGetZones)
		r.Post("/api/zones", s.handleCreateZone)
		r.Get("/api/zones/{origin}", s.handleGetZone)
		r.Delete("/api/zones/{origin}", s.handleDeleteZone)
		r.Get("/api/cache", s.handleGetCache)
		r.Delete("/api/cache", s.handleClearCache)
		r.Get("/api/config", s.handleGetConfig)
		r.Put("/api/config", s.handleUpdateConfig)

		// Multi-cluster and HA endpoints
		r.Get("/api/clusters", s.handleGetClusters)
		r.Get("/api/workers", s.handleGetWorkers)
		r.Get("/api/ha/status", s.handleGetHAStatus)
		r.Post("/api/ha/failover", s.handleHAFailover)

		// Distributed cache endpoints
		r.Get("/api/cache/distributed", s.handleGetDistributedCache)
		r.Delete("/api/cache/distributed", s.handleClearDistributedCache)
	})

	// Serve embedded frontend
	frontendFS := web.GetFS()
	if frontendFS != nil {
		// Serve static files
		r.Get("/*", s.serveFrontend(frontendFS))
	}

	return r
}

// serveFrontend serves the embedded React frontend with SPA fallback
func (s *Server) serveFrontend(frontendFS fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		// Try to open the requested file
		file, err := frontendFS.Open(path)
		if err != nil {
			// File not found, serve index.html for SPA routing
			file, err = frontendFS.Open("index.html")
			if err != nil {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			path = "index.html"
		}
		defer file.Close()

		// Get file info
		stat, err := file.Stat()
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// If it's a directory, try index.html
		if stat.IsDir() {
			file.Close()
			file, err = frontendFS.Open(path + "/index.html")
			if err != nil {
				// Fallback to root index.html for SPA
				file, err = frontendFS.Open("index.html")
				if err != nil {
					http.Error(w, "Not found", http.StatusNotFound)
					return
				}
			}
			stat, _ = file.Stat()
		}

		// Set content type based on extension
		contentType := "text/html"
		if strings.HasSuffix(path, ".js") {
			contentType = "application/javascript"
		} else if strings.HasSuffix(path, ".css") {
			contentType = "text/css"
		} else if strings.HasSuffix(path, ".json") {
			contentType = "application/json"
		} else if strings.HasSuffix(path, ".svg") {
			contentType = "image/svg+xml"
		} else if strings.HasSuffix(path, ".png") {
			contentType = "image/png"
		} else if strings.HasSuffix(path, ".ico") {
			contentType = "image/x-icon"
		}

		w.Header().Set("Content-Type", contentType)

		// Cache static assets
		if strings.Contains(path, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000")
		}

		// Copy file content to response
		io.Copy(w, file)
	}
}

// JWT Claims
type jwtClaims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Auth middleware
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from cookie
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			s.sendError(w, http.StatusUnauthorized, "Not authenticated")
			return
		}

		// Parse and validate token
		token, err := jwt.ParseWithClaims(cookie.Value, &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.jwtSecret, nil
		})

		if err != nil || !token.Valid {
			s.sendError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		claims, ok := token.Claims.(*jwtClaims)
		if !ok {
			s.sendError(w, http.StatusUnauthorized, "Invalid token claims")
			return
		}

		// Store claims in context
		ctx := context.WithValue(r.Context(), "username", claims.Username)
		ctx = context.WithValue(ctx, "role", claims.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Health check handler
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(s.startTime)
	resp := types.HealthResponse{
		Status:    "ok",
		Version:   "1.0.0",
		GoVersion: runtime.Version(),
		Uptime:    uptime.String(),
	}
	s.sendJSON(w, http.StatusOK, resp)
}

// Login handler
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req types.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate credentials
	if req.Username != s.config.API.Auth.Username {
		s.sendError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(s.passwordHash), []byte(req.Password)); err != nil {
		s.sendError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Create JWT token
	claims := jwtClaims{
		Username: req.Username,
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.API.Auth.TokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "Failed to create token")
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.config.API.Auth.TokenExpiry.Seconds()),
	})

	resp := types.AuthResponse{
		Success: true,
		User: types.UserInfo{
			Username: req.Username,
			Role:     "admin",
		},
	}
	s.sendJSON(w, http.StatusOK, resp)
}

// Logout handler
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	s.sendJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// Me handler
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	role := r.Context().Value("role").(string)

	resp := types.MeResponse{
		Authenticated: true,
		User: &types.UserInfo{
			Username: username,
			Role:     role,
		},
	}
	s.sendJSON(w, http.StatusOK, resp)
}

// Stats handler
func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats := s.buildStatsResponse()
	s.sendJSON(w, http.StatusOK, stats)
}

func (s *Server) buildStatsResponse() types.StatsResponse {
	// Get stats from DNS service
	ctx := context.Background()
	stats, err := s.dnsService.GetStats(ctx)
	if err != nil {
		// Return empty stats on error
		return types.StatsResponse{}
	}

	return types.StatsResponse{
		Server: types.ServerStats{
			Version:       stats.Server.Version,
			UptimeSeconds: stats.Server.UptimeSeconds,
			GoVersion:     stats.Server.GoVersion,
			NumCPU:        stats.Server.NumCPU,
			NumGoroutines: stats.Server.NumGoroutines,
			MemoryMB:      stats.Server.MemoryMB,
		},
		Cache: types.CacheStats{
			MessageCache: types.CacheTypeStats{
				Hits:      stats.Cache.MessageCache.Hits,
				Misses:    stats.Cache.MessageCache.Misses,
				Evicts:    stats.Cache.MessageCache.Evicts,
				HitRate:   stats.Cache.MessageCache.HitRate,
				SizeBytes: stats.Cache.MessageCache.SizeBytes,
			},
			RRsetCache: types.CacheTypeStats{
				Hits:      stats.Cache.RRsetCache.Hits,
				Misses:    stats.Cache.RRsetCache.Misses,
				Evicts:    stats.Cache.RRsetCache.Evicts,
				HitRate:   stats.Cache.RRsetCache.HitRate,
				SizeBytes: stats.Cache.RRsetCache.SizeBytes,
			},
		},
		Resolver: types.ResolverStats{
			InFlightQueries: stats.Resolver.InFlightQueries,
			Mode:            stats.Resolver.Mode,
		},
		Zones: types.ZonesStats{
			Count:        stats.Zones.Count,
			TotalRecords: stats.Zones.TotalRecords,
		},
	}
}

// SSE stats stream handler
func (s *Server) handleStatsSSE(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.sendError(w, http.StatusInternalServerError, "SSE not supported")
		return
	}

	// Create client channel
	clientChan := make(chan []byte, 10)
	s.sseRegister <- clientChan

	// Cleanup on disconnect
	defer func() {
		s.sseUnregister <- clientChan
	}()

	// Send initial stats
	stats := s.buildStatsResponse()
	data, _ := json.Marshal(stats)
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()

	// Stream updates
	for {
		select {
		case <-r.Context().Done():
			return
		case data := <-clientChan:
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// SSE broadcaster
func (s *Server) runSSEBroadcaster() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case client := <-s.sseRegister:
			s.sseMu.Lock()
			s.sseClients[client] = true
			s.sseMu.Unlock()
		case client := <-s.sseUnregister:
			s.sseMu.Lock()
			delete(s.sseClients, client)
			close(client)
			s.sseMu.Unlock()
		case <-ticker.C:
			s.broadcastStats()
		}
	}
}

func (s *Server) broadcastStats() {
	stats := s.buildStatsResponse()
	data, err := json.Marshal(stats)
	if err != nil {
		return
	}

	s.sseMu.RLock()
	defer s.sseMu.RUnlock()

	for client := range s.sseClients {
		select {
		case client <- data:
		default:
			// Client buffer full, skip
		}
	}
}

// Upstreams handlers
func (s *Server) handleGetUpstreams(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	upstreams, err := s.dnsService.GetUpstreams(ctx)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Convert bridge types to API types
	var upstreamInfos []types.UpstreamInfo
	for _, u := range upstreams {
		upstreamInfos = append(upstreamInfos, types.UpstreamInfo{
			Address:       u.Address,
			RTTMS:         u.RTTMS,
			Failures:      u.Failures,
			InFlight:      u.InFlight,
			LastSuccess:   u.LastSuccess,
			LastFailure:   u.LastFailure,
			TotalQueries:  u.TotalQueries,
			TotalFailures: u.TotalFailures,
			FailureRate:   u.FailureRate,
			Score:         u.Score,
			Healthy:       u.Healthy,
		})
	}

	resp := types.UpstreamsResponse{
		Upstreams: upstreamInfos,
	}
	s.sendJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUpdateUpstreams(w http.ResponseWriter, r *http.Request) {
	var req types.UpdateUpstreamsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Upstreams) == 0 {
		s.sendError(w, http.StatusBadRequest, "At least one upstream is required")
		return
	}

	ctx := r.Context()
	if err := s.dnsService.SetUpstreams(ctx, req.Upstreams); err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := types.UpdateUpstreamsResponse{
		Success:   true,
		Upstreams: req.Upstreams,
	}
	s.sendJSON(w, http.StatusOK, resp)
}

// Zone handlers
func (s *Server) handleGetZones(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	zones, err := s.dnsService.GetZones(ctx)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Convert bridge types to API types
	var zoneInfos []types.ZoneInfo
	for _, z := range zones {
		zoneInfos = append(zoneInfos, types.ZoneInfo{
			Origin:       z.Origin,
			Serial:       z.Serial,
			RecordCount:  z.RecordCount,
			LastModified: z.LastModified,
			HasSOA:       z.HasSOA,
		})
	}

	resp := types.ZonesResponse{Zones: zoneInfos}
	s.sendJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetZone(w http.ResponseWriter, r *http.Request) {
	origin := chi.URLParam(r, "origin")
	if origin == "" {
		s.sendError(w, http.StatusBadRequest, "Origin is required")
		return
	}

	ctx := r.Context()
	z, err := s.dnsService.GetZone(ctx, origin)
	if err != nil {
		s.sendError(w, http.StatusNotFound, "Zone not found")
		return
	}

	resp := types.ZoneDetailResponse{
		Origin:      z.Origin,
		Serial:      z.Serial,
		TransferACL: z.TransferACL,
		UpdateACL:   z.UpdateACL,
	}

	if z.SOA != nil {
		resp.SOA = &types.SOAInfo{
			PrimaryNS:  z.SOA.PrimaryNS,
			AdminEmail: z.SOA.AdminEmail,
			Serial:     z.SOA.Serial,
			Refresh:    z.SOA.Refresh,
			Retry:      z.SOA.Retry,
			Expire:     z.SOA.Expire,
			Minimum:    z.SOA.Minimum,
		}
	}

	// Convert records
	for _, rec := range z.Records {
		resp.Records = append(resp.Records, types.RecordInfo{
			Name: rec.Name,
			Type: rec.Type,
			TTL:  rec.TTL,
			Data: rec.Data,
		})
	}

	s.sendJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateZone(w http.ResponseWriter, r *http.Request) {
	var req types.CreateZoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Origin == "" {
		s.sendError(w, http.StatusBadRequest, "Origin is required")
		return
	}

	ctx := r.Context()
	z, err := s.dnsService.CreateZone(ctx, bridge.CreateZoneRequest{
		Origin:      req.Origin,
		TransferACL: req.TransferACL,
		UpdateACL:   req.UpdateACL,
	})
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := types.CreateZoneResponse{
		Success: true,
		Zone: types.ZoneDetailResponse{
			Origin:      z.Origin,
			Serial:      z.Serial,
			TransferACL: z.TransferACL,
			UpdateACL:   z.UpdateACL,
		},
	}
	s.sendJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleDeleteZone(w http.ResponseWriter, r *http.Request) {
	origin := chi.URLParam(r, "origin")
	if origin == "" {
		s.sendError(w, http.StatusBadRequest, "Origin is required")
		return
	}

	ctx := r.Context()
	if err := s.dnsService.DeleteZone(ctx, origin); err != nil {
		s.sendError(w, http.StatusNotFound, "Zone not found")
		return
	}

	resp := types.DeleteZoneResponse{
		Success: true,
		Origin:  origin,
	}
	s.sendJSON(w, http.StatusOK, resp)
}

// Cache handlers
func (s *Server) handleGetCache(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stats, err := s.dnsService.GetCacheStats(ctx)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := types.CacheResponse{
		MessageCache: types.CacheTypeStats{
			Hits:      stats.MessageCache.Hits,
			Misses:    stats.MessageCache.Misses,
			Evicts:    stats.MessageCache.Evicts,
			HitRate:   stats.MessageCache.HitRate,
			SizeBytes: stats.MessageCache.SizeBytes,
		},
		RRsetCache: types.CacheTypeStats{
			Hits:      stats.RRsetCache.Hits,
			Misses:    stats.RRsetCache.Misses,
			Evicts:    stats.RRsetCache.Evicts,
			HitRate:   stats.RRsetCache.HitRate,
			SizeBytes: stats.RRsetCache.SizeBytes,
		},
		InfraCache: types.InfraCacheInfo{
			ServerCount: stats.InfraCache.ServerCount,
		},
	}
	s.sendJSON(w, http.StatusOK, resp)
}

func (s *Server) handleClearCache(w http.ResponseWriter, r *http.Request) {
	var req types.ClearCacheRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ctx := r.Context()
	cleared, err := s.dnsService.ClearCache(ctx, req.CacheType)
	if err != nil {
		s.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp := types.ClearCacheResponse{
		Success: true,
		Cleared: cleared,
	}
	s.sendJSON(w, http.StatusOK, resp)
}

// Config handlers
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg, err := s.dnsService.GetConfig(ctx)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := types.ConfigResponse{
		Server: types.ServerConfigResponse{
			ListenAddress:               cfg.Server.ListenAddress,
			NumWorkers:                  cfg.Server.NumWorkers,
			EnableTCP:                   cfg.Server.EnableTCP,
			PprofAddress:                cfg.Server.PprofAddress,
			GracefulShutdownTimeoutSecs: cfg.Server.GracefulShutdownTimeoutSecs,
			StatsReportIntervalSecs:     cfg.Server.StatsReportIntervalSecs,
		},
		Cache: types.CacheConfigResponse{
			MessageCache: types.MessageCacheConfigResponse{
				MaxSizeMB: cfg.Cache.MessageCache.MaxSizeMB,
				NumShards: cfg.Cache.MessageCache.NumShards,
			},
			RRsetCache: types.RRsetCacheConfigResponse{
				MaxSizeMB: cfg.Cache.RRsetCache.MaxSizeMB,
				NumShards: cfg.Cache.RRsetCache.NumShards,
			},
			Prefetch: types.PrefetchConfigResponse{
				Enabled:             cfg.Cache.Prefetch.Enabled,
				ThresholdHits:       cfg.Cache.Prefetch.ThresholdHits,
				ThresholdTTLPercent: cfg.Cache.Prefetch.ThresholdTTLPercent,
			},
			MinTTLSecs: cfg.Cache.MinTTLSecs,
			MaxTTLSecs: cfg.Cache.MaxTTLSecs,
			NegTTLSecs: cfg.Cache.NegTTLSecs,
		},
		Resolver: types.ResolverConfigResponse{
			Mode:              cfg.Resolver.Mode,
			Upstreams:         cfg.Resolver.Upstreams,
			RootHintsFile:     cfg.Resolver.RootHintsFile,
			MaxRecursionDepth: cfg.Resolver.MaxRecursionDepth,
			QueryTimeoutSecs:  cfg.Resolver.QueryTimeoutSecs,
			EnableCoalescing:  cfg.Resolver.EnableCoalescing,
			Parallel: types.ParallelConfigResponse{
				NumParallel:         cfg.Resolver.Parallel.NumParallel,
				FallbackToRecursive: cfg.Resolver.Parallel.FallbackToRecursive,
				SuccessRcodes:       cfg.Resolver.Parallel.SuccessRcodes,
			},
		},
		Logging: types.LoggingConfigResponse{
			Level:          cfg.Logging.Level,
			Format:         cfg.Logging.Format,
			EnableQueryLog: cfg.Logging.EnableQueryLog,
		},
		API: types.APIConfigResponse{
			Enabled:       cfg.API.Enabled,
			ListenAddress: cfg.API.ListenAddress,
			CORSOrigins:   cfg.API.CORSOrigins,
		},
	}
	s.sendJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var req types.UpdateConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ctx := r.Context()
	updateReq := bridge.UpdateConfigRequest{}

	if req.Resolver != nil {
		updateReq.Resolver = &bridge.ResolverConfigUpdate{
			Mode:      req.Resolver.Mode,
			Upstreams: req.Resolver.Upstreams,
		}
	}

	if req.Logging != nil {
		updateReq.Logging = &bridge.LoggingConfigUpdate{
			Level:          req.Logging.Level,
			EnableQueryLog: req.Logging.EnableQueryLog,
		}
	}

	requiresRestart, err := s.dnsService.UpdateConfig(ctx, updateReq)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Get and return updated config
	cfg, err := s.dnsService.GetConfig(ctx)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := types.ConfigResponse{
		Server: types.ServerConfigResponse{
			ListenAddress:               cfg.Server.ListenAddress,
			NumWorkers:                  cfg.Server.NumWorkers,
			EnableTCP:                   cfg.Server.EnableTCP,
			PprofAddress:                cfg.Server.PprofAddress,
			GracefulShutdownTimeoutSecs: cfg.Server.GracefulShutdownTimeoutSecs,
			StatsReportIntervalSecs:     cfg.Server.StatsReportIntervalSecs,
		},
		Cache: types.CacheConfigResponse{
			MessageCache: types.MessageCacheConfigResponse{
				MaxSizeMB: cfg.Cache.MessageCache.MaxSizeMB,
				NumShards: cfg.Cache.MessageCache.NumShards,
			},
			RRsetCache: types.RRsetCacheConfigResponse{
				MaxSizeMB: cfg.Cache.RRsetCache.MaxSizeMB,
				NumShards: cfg.Cache.RRsetCache.NumShards,
			},
			Prefetch: types.PrefetchConfigResponse{
				Enabled:             cfg.Cache.Prefetch.Enabled,
				ThresholdHits:       cfg.Cache.Prefetch.ThresholdHits,
				ThresholdTTLPercent: cfg.Cache.Prefetch.ThresholdTTLPercent,
			},
			MinTTLSecs: cfg.Cache.MinTTLSecs,
			MaxTTLSecs: cfg.Cache.MaxTTLSecs,
			NegTTLSecs: cfg.Cache.NegTTLSecs,
		},
		Resolver: types.ResolverConfigResponse{
			Mode:              cfg.Resolver.Mode,
			Upstreams:         cfg.Resolver.Upstreams,
			RootHintsFile:     cfg.Resolver.RootHintsFile,
			MaxRecursionDepth: cfg.Resolver.MaxRecursionDepth,
			QueryTimeoutSecs:  cfg.Resolver.QueryTimeoutSecs,
			EnableCoalescing:  cfg.Resolver.EnableCoalescing,
			Parallel: types.ParallelConfigResponse{
				NumParallel:         cfg.Resolver.Parallel.NumParallel,
				FallbackToRecursive: cfg.Resolver.Parallel.FallbackToRecursive,
				SuccessRcodes:       cfg.Resolver.Parallel.SuccessRcodes,
			},
		},
		Logging: types.LoggingConfigResponse{
			Level:          cfg.Logging.Level,
			Format:         cfg.Logging.Format,
			EnableQueryLog: cfg.Logging.EnableQueryLog,
		},
		API: types.APIConfigResponse{
			Enabled:       cfg.API.Enabled,
			ListenAddress: cfg.API.ListenAddress,
			CORSOrigins:   cfg.API.CORSOrigins,
		},
	}

	// Add note about restart requirement
	if requiresRestart {
		// Could add this to response if needed
		_ = requiresRestart
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// Clusters handler - returns mock data for standalone mode
func (s *Server) handleGetClusters(w http.ResponseWriter, r *http.Request) {
	// In standalone mode, return a single local cluster
	// In distributed mode, this would query the control plane
	hostname, _ := os.Hostname()

	clusters := []types.ClusterInfo{
		{
			Name:           "local",
			DisplayName:    "Local Cluster",
			Region:         "local",
			Zone:           "default",
			Status:         "healthy",
			LastHeartbeat:  time.Now(),
			WorkerCount:    1,
			HealthyWorkers: 1,
			Labels: map[string]string{
				"environment": "standalone",
				"hostname":    hostname,
			},
			Capacity: types.ClusterCapacity{
				MaxWorkers:       10,
				CurrentWorkers:   1,
				AvailableWorkers: 9,
			},
		},
	}

	resp := types.ClustersResponse{
		Clusters:       clusters,
		TotalWorkers:   1,
		HealthyWorkers: 1,
	}
	s.sendJSON(w, http.StatusOK, resp)
}

// Workers handler - returns mock data for standalone mode
func (s *Server) handleGetWorkers(w http.ResponseWriter, r *http.Request) {
	// In standalone mode, return the local server as a worker
	// In distributed mode, this would query the control plane
	hostname, _ := os.Hostname()

	// Get current stats to populate metrics
	stats := s.buildStatsResponse()

	// Calculate QPS - avoid division by zero and round to 2 decimal places
	var qps float64
	if stats.Server.UptimeSeconds > 0 {
		totalQueries := float64(stats.Cache.MessageCache.Hits + stats.Cache.MessageCache.Misses)
		qps = math.Round(totalQueries/stats.Server.UptimeSeconds*100) / 100
	}

	workers := []types.WorkerInfo{
		{
			ID:            hostname + "-standalone",
			ClusterName:   "local",
			Region:        "local",
			Zone:          "default",
			Status:        "healthy",
			Address:       s.config.Server.ListenAddress,
			LastHeartbeat: time.Now(),
			Metrics: types.WorkerMetrics{
				QPS:          qps,
				CacheHitRate: math.Round(stats.Cache.MessageCache.HitRate*100*100) / 100, // Round to 2 decimals
				MemoryMB:     math.Round(stats.Server.MemoryMB*100) / 100,
				CPUPercent:   0, // Not tracked in standalone mode
				Uptime:       stats.Server.UptimeSeconds,
			},
		},
	}

	resp := types.WorkersResponse{
		Workers:    workers,
		TotalCount: 1,
		ByCluster:  map[string]int{"local": 1},
		ByRegion:   map[string]int{"local": 1},
	}
	s.sendJSON(w, http.StatusOK, resp)
}

// HA Status handler - returns mock data for standalone mode
func (s *Server) handleGetHAStatus(w http.ResponseWriter, r *http.Request) {
	// In standalone mode, HA is disabled
	// In distributed mode, this would return actual HA status
	hostname, _ := os.Hostname()

	resp := types.HAStatusResponse{
		Enabled: false,
		Mode:    "standalone",
		Leader: types.HALeaderInfo{
			IsLeader:      true,
			LeaderID:      hostname,
			LeaderCluster: "local",
			LeaseExpiry:   time.Now().Add(24 * time.Hour), // Never expires in standalone
			LastRenewal:   time.Now(),
		},
		Quorum: types.HAQuorumInfo{
			HasQuorum:       true,
			QuorumType:      "single-node",
			VotersTotal:     1,
			VotersReachable: 1,
			ClusterVotes: []types.ClusterVoteInfo{
				{
					ClusterID:     "local",
					WorkersTotal:  1,
					WorkersVoting: 1,
					LastHeartbeat: time.Now(),
					VoteValid:     true,
				},
			},
			LastCheck:       time.Now(),
			QuorumLostSince: nil,
		},
		Fencing: types.HAFencingInfo{
			IsFenced:       false,
			Reason:         "",
			QuorumLostAt:   nil,
			GracePeriodEnd: nil,
		},
		ControlPlanes: []types.ControlPlaneInstance{
			{
				ID:            hostname,
				ClusterRef:    "local",
				Priority:      1,
				IsLeader:      true,
				Status:        "active",
				LastHeartbeat: time.Now(),
				Address:       s.config.API.ListenAddress,
			},
		},
	}
	s.sendJSON(w, http.StatusOK, resp)
}

// HA Failover handler - not available in standalone mode
func (s *Server) handleHAFailover(w http.ResponseWriter, r *http.Request) {
	// In standalone mode, failover is not supported
	resp := types.HAFailoverResponse{
		Success:   false,
		Message:   "Failover not available in standalone mode",
		NewLeader: "",
	}
	s.sendError(w, http.StatusBadRequest, resp.Message)
}

// Distributed Cache handler - returns cache info across all workers
func (s *Server) handleGetDistributedCache(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()

	// Get current cache stats
	ctx := r.Context()
	cacheStats, err := s.dnsService.GetCacheStats(ctx)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Build per-worker cache info (in standalone mode, just one worker)
	workerCache := types.WorkerCacheInfo{
		WorkerID:    hostname + "-standalone",
		ClusterName: "local",
		Address:     s.config.Server.ListenAddress,
		Status:      "healthy",
		MessageCache: types.CacheTypeStats{
			Hits:         cacheStats.MessageCache.Hits,
			Misses:       cacheStats.MessageCache.Misses,
			Evicts:       cacheStats.MessageCache.Evicts,
			HitRate:      math.Round(cacheStats.MessageCache.HitRate*10000) / 100, // Convert to percentage with 2 decimals
			SizeBytes:    cacheStats.MessageCache.SizeBytes,
			MaxSizeBytes: cacheStats.MessageCache.MaxSizeBytes,
			NumShards:    cacheStats.MessageCache.NumShards,
		},
		RRsetCache: types.CacheTypeStats{
			Hits:         cacheStats.RRsetCache.Hits,
			Misses:       cacheStats.RRsetCache.Misses,
			Evicts:       cacheStats.RRsetCache.Evicts,
			HitRate:      math.Round(cacheStats.RRsetCache.HitRate*10000) / 100,
			SizeBytes:    cacheStats.RRsetCache.SizeBytes,
			MaxSizeBytes: cacheStats.RRsetCache.MaxSizeBytes,
			NumShards:    cacheStats.RRsetCache.NumShards,
		},
		InfraCache: types.InfraCacheInfo{
			ServerCount: cacheStats.InfraCache.ServerCount,
		},
		LastUpdated: time.Now(),
	}

	// Calculate aggregated stats
	aggregated := types.AggregatedCacheStats{
		TotalHits:         cacheStats.MessageCache.Hits + cacheStats.RRsetCache.Hits,
		TotalMisses:       cacheStats.MessageCache.Misses + cacheStats.RRsetCache.Misses,
		TotalEvicts:       cacheStats.MessageCache.Evicts + cacheStats.RRsetCache.Evicts,
		AverageHitRate:    math.Round((cacheStats.MessageCache.HitRate+cacheStats.RRsetCache.HitRate)/2*10000) / 100,
		TotalSizeBytes:    cacheStats.MessageCache.SizeBytes + cacheStats.RRsetCache.SizeBytes,
		TotalMaxSizeBytes: cacheStats.MessageCache.MaxSizeBytes + cacheStats.RRsetCache.MaxSizeBytes,
		WorkerCount:       1,
	}

	// Build architecture description
	architecture := types.CacheArchitectureInfo{
		Description:  "Standalone mode: Local L1 message cache + Local L2 RRset cache per worker",
		L1Type:       "local-message-cache",
		L2Type:       "local-rrset-cache",
		Replication:  "none",
		Invalidation: "local-only",
		Features:     []string{"two-level-cache", "negative-caching", "prefetch"},
	}

	resp := types.DistributedCacheResponse{
		Mode:         "standalone",
		Workers:      []types.WorkerCacheInfo{workerCache},
		SharedCache:  nil, // No shared cache in standalone mode
		Aggregated:   aggregated,
		Architecture: architecture,
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// Clear Distributed Cache handler - clears cache across workers
func (s *Server) handleClearDistributedCache(w http.ResponseWriter, r *http.Request) {
	var req types.ClearDistributedCacheRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Default to clearing all caches on all workers
		req = types.ClearDistributedCacheRequest{
			Target:    "all",
			CacheType: "all",
		}
	}

	hostname, _ := os.Hostname()
	workerID := hostname + "-standalone"

	// In standalone mode, we only have one worker
	ctx := r.Context()
	cleared, err := s.dnsService.ClearCache(ctx, req.CacheType)
	if err != nil {
		s.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	result := types.WorkerClearResult{
		WorkerID: workerID,
		Success:  true,
		Cleared:  cleared,
	}

	resp := types.ClearDistributedCacheResponse{
		Success:       true,
		ClearedCount:  1,
		Results:       []types.WorkerClearResult{result},
		SharedCleared: false, // No shared cache in standalone mode
	}

	s.sendJSON(w, http.StatusOK, resp)
}

// Helper functions
func (s *Server) sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) sendError(w http.ResponseWriter, status int, message string) {
	resp := types.APIResponse{
		Success:   false,
		Error:     message,
		Timestamp: time.Now(),
	}
	s.sendJSON(w, status, resp)
}

// typeToString converts DNS type to string
func typeToString(t uint16) string {
	types := map[uint16]string{
		1:   "A",
		2:   "NS",
		5:   "CNAME",
		6:   "SOA",
		12:  "PTR",
		15:  "MX",
		16:  "TXT",
		28:  "AAAA",
		33:  "SRV",
		257: "CAA",
	}
	if s, ok := types[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

// generateRandomString generates a random base64 string
func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
