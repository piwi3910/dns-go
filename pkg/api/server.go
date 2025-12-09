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
	"net/http"
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
	"github.com/piwi3910/dns-go/pkg/config"
	"github.com/piwi3910/dns-go/pkg/resolver"
	"github.com/piwi3910/dns-go/pkg/server"
	"github.com/piwi3910/dns-go/pkg/zone"
	"github.com/piwi3910/dns-go/web"
)

const (
	cookieName     = "dns_session"
	defaultPassword = "admin"
)

// Server is the API server for the DNS management GUI.
type Server struct {
	config      *config.Config
	handler     *server.Handler
	zoneManager *zone.Manager
	upstream    *resolver.UpstreamPool
	jwtSecret   []byte
	passwordHash string
	startTime   time.Time
	httpServer  *http.Server

	// SSE broadcaster
	sseClients   map[chan []byte]bool
	sseRegister  chan chan []byte
	sseUnregister chan chan []byte
	sseMu        sync.RWMutex
}

// NewServer creates a new API server.
func NewServer(cfg *config.Config, handler *server.Handler, zoneManager *zone.Manager, upstream *resolver.UpstreamPool) *Server {
	s := &Server{
		config:        cfg,
		handler:       handler,
		zoneManager:   zoneManager,
		upstream:      upstream,
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
	handlerStats := s.handler.GetStats()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Determine resolver mode string
	modeStr := "unknown"
	switch s.config.Resolver.Mode {
	case "forwarding":
		modeStr = "forwarding"
	case "recursive":
		modeStr = "recursive"
	case "parallel":
		modeStr = "parallel"
	}

	// Count zones
	zoneCount := 0
	totalRecords := 0
	if s.zoneManager != nil {
		origins := s.zoneManager.GetAllZones()
		zoneCount = len(origins)
		for _, origin := range origins {
			if z := s.zoneManager.GetZone(origin); z != nil {
				totalRecords += z.RecordCount()
			}
		}
	}

	return types.StatsResponse{
		Server: types.ServerStats{
			Version:       "1.0.0",
			UptimeSeconds: time.Since(s.startTime).Seconds(),
			GoVersion:     runtime.Version(),
			NumCPU:        runtime.NumCPU(),
			NumGoroutines: runtime.NumGoroutine(),
			MemoryMB:      float64(memStats.Alloc) / 1024 / 1024,
		},
		Cache: types.CacheStats{
			MessageCache: types.CacheTypeStats{
				Hits:      handlerStats.MessageCache.Hits,
				Misses:    handlerStats.MessageCache.Misses,
				Evicts:    handlerStats.MessageCache.Evicts,
				HitRate:   handlerStats.MessageCache.HitRate,
				SizeBytes: handlerStats.MessageCache.Size,
			},
			RRsetCache: types.CacheTypeStats{
				Hits:      handlerStats.RRsetCache.Hits,
				Misses:    handlerStats.RRsetCache.Misses,
				Evicts:    handlerStats.RRsetCache.Evicts,
				HitRate:   handlerStats.RRsetCache.HitRate,
				SizeBytes: handlerStats.RRsetCache.Size,
			},
		},
		Resolver: types.ResolverStats{
			InFlightQueries: 0, // TODO: expose from resolver
			Mode:            modeStr,
		},
		Zones: types.ZonesStats{
			Count:        zoneCount,
			TotalRecords: totalRecords,
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
	upstreams := s.upstream.GetUpstreams()
	stats := s.upstream.GetStats()

	// Create map for quick lookup
	statsMap := make(map[string]interface{})
	for _, stat := range stats {
		statsMap[stat.Address] = stat
	}

	var upstreamInfos []types.UpstreamInfo
	for _, addr := range upstreams {
		info := types.UpstreamInfo{
			Address: addr,
			Healthy: true,
		}

		if stat, ok := statsMap[addr]; ok {
			// Type assert to get the actual stats
			if s, ok := stat.(interface {
				GetSnapshot() interface{}
			}); ok {
				_ = s // Use the snapshot
			}
		}

		upstreamInfos = append(upstreamInfos, info)
	}

	// Get detailed stats from infra cache
	for i, stat := range stats {
		if i < len(upstreamInfos) {
			upstreamInfos[i].RTTMS = stat.RTT
			upstreamInfos[i].Failures = stat.Failures
			upstreamInfos[i].InFlight = stat.InFlight
			upstreamInfos[i].LastSuccess = stat.LastSuccess
			upstreamInfos[i].LastFailure = stat.LastFailure
			upstreamInfos[i].TotalQueries = stat.TotalQueries
			upstreamInfos[i].TotalFailures = stat.TotalFailures
			upstreamInfos[i].FailureRate = stat.FailureRate
			upstreamInfos[i].Score = stat.Score
			upstreamInfos[i].Healthy = stat.FailureRate < 0.5
		}
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

	s.upstream.SetUpstreams(req.Upstreams)

	resp := types.UpdateUpstreamsResponse{
		Success:   true,
		Upstreams: req.Upstreams,
	}
	s.sendJSON(w, http.StatusOK, resp)
}

// Zone handlers
func (s *Server) handleGetZones(w http.ResponseWriter, r *http.Request) {
	if s.zoneManager == nil {
		s.sendJSON(w, http.StatusOK, types.ZonesResponse{Zones: []types.ZoneInfo{}})
		return
	}

	origins := s.zoneManager.GetAllZones()
	var zones []types.ZoneInfo

	for _, origin := range origins {
		z := s.zoneManager.GetZone(origin)
		if z == nil {
			continue
		}

		zones = append(zones, types.ZoneInfo{
			Origin:       z.Origin,
			Serial:       z.GetSerial(),
			RecordCount:  z.RecordCount(),
			LastModified: z.LastModified,
			HasSOA:       z.SOA != nil,
		})
	}

	resp := types.ZonesResponse{Zones: zones}
	s.sendJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetZone(w http.ResponseWriter, r *http.Request) {
	origin := chi.URLParam(r, "origin")
	if origin == "" {
		s.sendError(w, http.StatusBadRequest, "Origin is required")
		return
	}

	if s.zoneManager == nil {
		s.sendError(w, http.StatusNotFound, "Zone not found")
		return
	}

	z := s.zoneManager.GetZone(origin)
	if z == nil {
		s.sendError(w, http.StatusNotFound, "Zone not found")
		return
	}

	resp := types.ZoneDetailResponse{
		Origin:      z.Origin,
		Serial:      z.GetSerial(),
		TransferACL: z.TransferACL,
		UpdateACL:   z.UpdateACL,
	}

	if z.SOA != nil {
		resp.SOA = &types.SOAInfo{
			PrimaryNS:  z.SOA.Ns,
			AdminEmail: z.SOA.Mbox,
			Serial:     z.SOA.Serial,
			Refresh:    z.SOA.Refresh,
			Retry:      z.SOA.Retry,
			Expire:     z.SOA.Expire,
			Minimum:    z.SOA.Minttl,
		}
	}

	// Get all records
	allRecords := z.GetAllRecordsOrdered()
	for _, rr := range allRecords {
		resp.Records = append(resp.Records, types.RecordInfo{
			Name: rr.Header().Name,
			Type: typeToString(rr.Header().Rrtype),
			TTL:  rr.Header().Ttl,
			Data: rr.String(),
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

	if s.zoneManager == nil {
		s.sendError(w, http.StatusInternalServerError, "Zone manager not available")
		return
	}

	// Create zone
	z := zone.NewZone(zone.Config{
		Origin:      req.Origin,
		TransferACL: req.TransferACL,
		UpdateACL:   req.UpdateACL,
	})

	s.zoneManager.AddZone(z)

	resp := types.CreateZoneResponse{
		Success: true,
		Zone: types.ZoneDetailResponse{
			Origin:      z.Origin,
			Serial:      z.GetSerial(),
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

	if s.zoneManager == nil {
		s.sendError(w, http.StatusNotFound, "Zone not found")
		return
	}

	s.zoneManager.RemoveZone(origin)

	resp := types.DeleteZoneResponse{
		Success: true,
		Origin:  origin,
	}
	s.sendJSON(w, http.StatusOK, resp)
}

// Cache handlers
func (s *Server) handleGetCache(w http.ResponseWriter, r *http.Request) {
	stats := s.handler.GetStats()

	resp := types.CacheResponse{
		MessageCache: types.CacheTypeStats{
			Hits:      stats.MessageCache.Hits,
			Misses:    stats.MessageCache.Misses,
			Evicts:    stats.MessageCache.Evicts,
			HitRate:   stats.MessageCache.HitRate,
			SizeBytes: stats.MessageCache.Size,
		},
		RRsetCache: types.CacheTypeStats{
			Hits:      stats.RRsetCache.Hits,
			Misses:    stats.RRsetCache.Misses,
			Evicts:    stats.RRsetCache.Evicts,
			HitRate:   stats.RRsetCache.HitRate,
			SizeBytes: stats.RRsetCache.Size,
		},
		InfraCache: types.InfraCacheInfo{
			ServerCount: len(s.upstream.GetUpstreams()),
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

	var cleared []string
	switch req.CacheType {
	case "all":
		s.handler.ClearCaches()
		cleared = []string{"message", "rrset", "infra"}
	case "message":
		// TODO: Add individual cache clear methods
		s.handler.ClearCaches()
		cleared = []string{"message"}
	case "rrset":
		s.handler.ClearCaches()
		cleared = []string{"rrset"}
	case "infra":
		s.handler.ClearCaches()
		cleared = []string{"infra"}
	default:
		s.sendError(w, http.StatusBadRequest, "Invalid cache type")
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
	cfg := s.config

	resp := types.ConfigResponse{
		Server: types.ServerConfigResponse{
			ListenAddress:               cfg.Server.ListenAddress,
			NumWorkers:                  cfg.Server.NumWorkers,
			EnableTCP:                   cfg.Server.EnableTCP,
			PprofAddress:                cfg.Server.PprofAddress,
			GracefulShutdownTimeoutSecs: int(cfg.Server.GracefulShutdownTimeout.Seconds()),
			StatsReportIntervalSecs:     int(cfg.Server.StatsReportInterval.Seconds()),
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
			MinTTLSecs: int(cfg.Cache.MinTTL.Seconds()),
			MaxTTLSecs: int(cfg.Cache.MaxTTL.Seconds()),
			NegTTLSecs: int(cfg.Cache.NegativeTTL.Seconds()),
		},
		Resolver: types.ResolverConfigResponse{
			Mode:              cfg.Resolver.Mode,
			Upstreams:         cfg.Resolver.Upstreams,
			RootHintsFile:     cfg.Resolver.RootHintsFile,
			MaxRecursionDepth: cfg.Resolver.MaxRecursionDepth,
			QueryTimeoutSecs:  int(cfg.Resolver.QueryTimeout.Seconds()),
			EnableCoalescing:  cfg.Resolver.EnableCoalescing,
			Parallel: types.ParallelConfigResponse{
				NumParallel:         cfg.Resolver.ParallelConfig.NumParallel,
				FallbackToRecursive: cfg.Resolver.ParallelConfig.FallbackToRecursive,
				SuccessRcodes:       cfg.Resolver.ParallelConfig.SuccessRcodes,
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

	// Apply updates
	if req.Resolver != nil {
		if req.Resolver.Upstreams != nil {
			s.upstream.SetUpstreams(req.Resolver.Upstreams)
			s.config.Resolver.Upstreams = req.Resolver.Upstreams
		}
		if req.Resolver.Mode != nil {
			s.config.Resolver.Mode = *req.Resolver.Mode
			// Note: Mode change requires restart to take effect
		}
	}

	if req.Logging != nil {
		if req.Logging.Level != nil {
			s.config.Logging.Level = *req.Logging.Level
		}
		if req.Logging.EnableQueryLog != nil {
			s.config.Logging.EnableQueryLog = *req.Logging.EnableQueryLog
		}
	}

	// Return updated config
	s.handleGetConfig(w, r)
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
