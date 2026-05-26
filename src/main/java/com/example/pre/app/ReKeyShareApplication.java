package com.example.pre.app;

import com.example.pre.crypto.PreScheme;
import com.example.pre.crypto.EncryptedKeyCapsule;
import com.example.pre.crypto.ecc.EccPreScheme;
import com.example.pre.crypto.rsa.RsaCommonModulusParameters;
import com.example.pre.crypto.rsa.RsaPreScheme;
import com.example.pre.crypto.provider.SchemeDescriptor;
import com.example.pre.crypto.provider.CryptoProviderRegistry;
import com.example.pre.model.AccessPolicy;
import com.example.pre.model.AlgorithmType;
import com.example.pre.model.AuditEvent;
import com.example.pre.model.CapsuleContext;
import com.example.pre.model.EncryptedDataPackage;
import com.example.pre.model.ReEncryptedPackage;
import com.example.pre.model.RecipientShareSubmission;
import com.example.pre.model.ReKeySession;
import com.example.pre.model.ShareGrant;
import com.example.pre.model.SharedPackageV2;
import com.example.pre.model.User;
import com.example.pre.model.UserRole;
import com.example.pre.service.AuditService;
import com.example.pre.service.AuditProofService;
import com.example.pre.service.AuthorizationService;
import com.example.pre.service.BenchmarkResultService;
import com.example.pre.service.DataSecurityService;
import com.example.pre.service.DemoPrivateKeyStore;
import com.example.pre.service.DemoRecipientShareSignature;
import com.example.pre.service.DemoTokenService;
import com.example.pre.service.EccRecipientShareService;
import com.example.pre.service.ErrorCode;
import com.example.pre.service.KeyManagementService;
import com.example.pre.service.IdempotencyService;
import com.example.pre.service.ObjectAuthorizationService;
import com.example.pre.service.PackageVerifier;
import com.example.pre.service.ProxyReEncryptionService;
import com.example.pre.service.ProxyNodeService;
import com.example.pre.service.ReKeyShareException;
import com.example.pre.service.RevocationService;
import com.example.pre.service.SchemeRegistry;
import com.example.pre.service.SecurityContext;
import com.example.pre.service.StorageSnapshotService;
import com.example.pre.service.UserService;
import com.example.pre.crypto.ecc.RecipientReKeyShare;
import com.example.pre.storage.InMemoryAuditRepository;
import com.example.pre.storage.InMemoryDataRepository;
import com.example.pre.storage.InMemoryGrantRepository;
import com.example.pre.storage.InMemoryKeyRepository;
import com.example.pre.storage.InMemoryReEncryptedPackageRepository;
import com.example.pre.storage.InMemoryUserRepository;
import com.example.pre.util.JsonFields;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.math.BigInteger;
import java.time.Instant;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Base64;
import java.util.UUID;
import java.util.ArrayDeque;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class ReKeyShareApplication {
    private static final int MAX_BODY_BYTES = 1024 * 1024;

    private ReKeyShareApplication() {
    }

    public record RunningServer(HttpServer server, int port) {
        public void stop() {
            server.stop(0);
        }
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        RunningServer running = start(port);
        System.out.println("ReKeyShare API listening on http://localhost:" + running.port());
        System.out.println("Security profile: " + RuntimeProfile.fromProperty());
        System.out.println("OpenAPI catalog: http://localhost:" + running.port() + "/openapi.json");
        System.out.println("Audit verification: http://localhost:" + running.port() + "/api/audit/verify");
    }

    public static RunningServer start(int requestedPort) throws IOException {
        return start(requestedPort, RuntimeProfile.fromProperty());
    }

    public static RunningServer startDemo(int requestedPort) throws IOException {
        return start(requestedPort, RuntimeProfile.DEMO);
    }

    public static RunningServer start(int requestedPort, RuntimeProfile profile) throws IOException {
        ApiState state = new ApiState(profile);
        HttpServer server = HttpServer.create(new InetSocketAddress(requestedPort), 0);
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "rekeyshare-http-worker");
            thread.setDaemon(true);
            return thread;
        }));
        server.createContext("/", exchange -> route(exchange, state));
        server.start();
        return new RunningServer(server, server.getAddress().getPort());
    }

    private static void route(HttpExchange exchange, ApiState state) throws IOException {
        String requestId = "req-" + UUID.randomUUID();
        String remote = exchange.getRemoteAddress() == null ? "local" : exchange.getRemoteAddress().getAddress().getHostAddress();
        try {
            state.rateLimiter.assertAllowed(remote);
            String path = exchange.getRequestURI().getPath();
            if (path.startsWith("/api/v1/")) {
                path = "/api/" + path.substring("/api/v1/".length());
            }
            String method = exchange.getRequestMethod();
            enforceContentType(exchange, method);
            Map<String, String> body = readFields(exchange);
            DemoTokenService.AuthenticatedActor auth = publicEndpoint(method, path)
                    ? new DemoTokenService.AuthenticatedActor("anonymous", UserRole.RECIPIENT, "public", "public", 0, Long.MAX_VALUE)
                    : actor(exchange, body, state);
            SecurityContext security = auth.securityContext();
            String actor = auth.userId();
            IdempotencyService.Decision idempotency = beginIdempotency(exchange, state, method, path, actor, body);
            if (idempotency != null && idempotency.replayed()) {
                writeJson(exchange, idempotency.replay().status(), idempotency.replay().body());
                return;
            }
            if (idempotency != null) {
                exchange.setAttribute("rekeyshare.idempotency",
                        new PendingResponse(state.idempotency, idempotency.pending()));
            }

            if ("GET".equals(method) && "/".equals(path)) {
                writeJson(exchange, 200, "{\"name\":\"ReKeyShare\",\"status\":\"running\",\"openapi\":\"/openapi.json\"}");
            } else if ("GET".equals(method) && "/openapi.json".equals(path)) {
                writeJson(exchange, 200, openApiJson(state.profile));
            } else if ("POST".equals(method) && "/api/users".equals(path)) {
                createUser(exchange, state, body);
            } else if ("POST".equals(method) && "/api/auth/login".equals(path)) {
                login(exchange, state, body);
            } else if ("GET".equals(method) && "/api/users".equals(path)) {
                writeJson(exchange, 200, "{\"count\":" + state.users.findAll().size() + "}");
            } else if ("POST".equals(method) && path.matches("/api/users/[^/]+/keys")) {
                createKey(exchange, state, auth, segment(path, 3));
            } else if ("POST".equals(method) && path.matches("/api/users/[^/]+/keys/rotate")) {
                requireDemoFeature(state, path);
                rotateUserKey(exchange, state, actor, segment(path, 3));
            } else if ("POST".equals(method) && "/api/data/upload".equals(path)) {
                requireDemoFeature(state, path);
                uploadData(exchange, state, actor, body);
            } else if ("POST".equals(method) && "/api/data/upload-encrypted".equals(path)) {
                uploadEncryptedData(exchange, state, actor, body);
            } else if ("GET".equals(method) && path.matches("/api/data/[^/]+")) {
                getData(exchange, state, actor, segment(path, 3));
            } else if ("POST".equals(method) && "/api/grants".equals(path)) {
                createGrant(exchange, state, actor, body);
            } else if ("POST".equals(method) && "/api/grants/ecc".equals(path)) {
                createEccGrant(exchange, state, actor, body);
            } else if ("GET".equals(method) && "/api/grants".equals(path)) {
                writeJson(exchange, 200, "{\"count\":" + state.grants.findAll().size() + "}");
            } else if ("POST".equals(method) && path.matches("/api/grants/[^/]+/revoke")) {
                revokeGrant(exchange, state, actor, segment(path, 3));
            } else if ("POST".equals(method) && "/api/rekey-sessions".equals(path)) {
                createReKeySession(exchange, state, actor, body);
            } else if ("POST".equals(method) && path.matches("/api/rekey-sessions/[^/]+/recipient-share")) {
                submitRecipientShare(exchange, state, actor, segment(path, 3), body);
            } else if ("POST".equals(method) && path.matches("/api/rekey-sessions/[^/]+/recipient-share-demo")) {
                requireDemoFeature(state, path);
                submitRecipientShareDemo(exchange, state, actor, segment(path, 3));
            } else if ("POST".equals(method) && "/api/proxy/re-encrypt".equals(path)) {
                requireRole(auth, UserRole.PROXY);
                proxyReEncrypt(exchange, state, security, body);
            } else if ("POST".equals(method) && "/api/proxy-nodes".equals(path)) {
                requireAdmin(auth);
                registerProxyNode(exchange, state, actor, body);
            } else if ("POST".equals(method) && path.matches("/api/proxy-nodes/[^/]+/revoke")) {
                requireAdmin(auth);
                revokeProxyNode(exchange, state, actor, segment(path, 3));
            } else if ("GET".equals(method) && path.matches("/api/shared-packages/[^/]+")) {
                getSharedPackage(exchange, state, actor, segment(path, 3));
            } else if (state.profile.demoFeaturesEnabled() && "GET".equals(method) && path.matches("/api/demo/shared-packages/[^/]+/decrypt")) {
                demoDecryptSharedPackage(exchange, state, actor, segment(path, 4));
            } else if ("GET".equals(method) && "/api/audit/events".equals(path)) {
                requireAdmin(auth);
                auditEvents(exchange, state);
            } else if ("GET".equals(method) && path.matches("/api/audit/data/[^/]+")) {
                requireAdmin(auth);
                String dataId = segment(path, 4);
                long count = state.audit.events().stream().filter(event -> dataId.equals(event.target()) || dataId.equals(event.dataId())).count();
                writeJson(exchange, 200, "{\"code\":\"SUCCESS\",\"dataId\":\"" + json(dataId) + "\",\"count\":" + count + "}");
            } else if ("GET".equals(method) && "/api/audit/export".equals(path)) {
                requireAdmin(auth);
                auditEvents(exchange, state);
            } else if ("GET".equals(method) && "/api/audit/root".equals(path)) {
                requireAdmin(auth);
                AuditService.AuditVerificationResult result = state.audit.verifyChain();
                writeJson(exchange, 200, "{\"rootHash\":\"" + result.rootHash() + "\",\"checkedEvents\":" + result.checkedEvents() + "}");
            } else if ("GET".equals(method) && "/api/audit/proof".equals(path)) {
                requireAdmin(auth);
                AuditProofService.AuditProof proof = state.auditProof.createProof(state.audit.events());
                writeJson(exchange, 200, state.auditProof.exportJson(proof));
            } else if ("GET".equals(method) && "/api/audit/verify".equals(path)) {
                requireAdmin(auth);
                auditVerify(exchange, state);
            } else if ("POST".equals(method) && "/api/audit/tamper-demo".equals(path)) {
                requireAdmin(auth);
                if (state.auditRepository.findAll().size() > 1) {
                    state.auditRepository.replaceForDemo(1, state.auditRepository.findAll().get(1).withAction("TAMPER_DEMO"));
                }
                AuditService.AuditVerificationResult result = state.audit.verifyChain();
                writeJson(exchange, 200, "{\"valid\":" + result.valid() + ",\"brokenAt\":"
                        + (result.brokenAt() == null ? "null" : result.brokenAt()) + "}");
            } else if ("POST".equals(method) && "/api/benchmark/run".equals(path)) {
                requireAdmin(auth);
                BenchmarkApplication.main(new String[0]);
                state.audit.record("benchmark", "BENCHMARK_RUN", "docs/reports/raw/e02-algorithm-benchmark.csv", true, "api");
                writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"result\":\"docs/reports/raw/e02-algorithm-benchmark.csv\"}");
            } else if ("GET".equals(method) && "/api/benchmark/results".equals(path)) {
                requireAdmin(auth);
                writeJson(exchange, 200, "{\"code\":\"SUCCESS\",\"result\":\"docs/reports/raw/e02-algorithm-benchmark.csv\"}");
            } else if ("GET".equals(method) && "/api/benchmark/summary".equals(path)) {
                requireAdmin(auth);
                writeJson(exchange, 200, state.benchmark.summaryJson(Path.of("docs", "reports", "raw", "e02-algorithm-benchmark.csv")));
            } else if ("POST".equals(method) && "/api/storage/export".equals(path)) {
                requireAdmin(auth);
                Path output = Path.of("storage", "exports", "rekeyshare-snapshot.json");
                String snapshotHash = state.storage.exportSnapshotHash(output);
                state.audit.record(actor, "STORAGE_EXPORT", output.toString(), true, "json snapshot");
                writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"path\":\"" + json(output.toString())
                        + "\",\"snapshotHash\":\"" + snapshotHash + "\"}");
            } else if ("POST".equals(method) && "/api/storage/import-check".equals(path)) {
                requireAdmin(auth);
                Path input = Path.of(body.getOrDefault("path", "storage/exports/rekeyshare-snapshot.json"));
                String expectedHash = body.get("snapshotHash");
                boolean valid = state.storage.verifySnapshot(input, expectedHash);
                writeJson(exchange, 200, "{\"code\":\"SUCCESS\",\"path\":\"" + json(input.toString())
                        + "\",\"valid\":" + valid + "}");
            } else if ("POST".equals(method) && "/api/storage/export-index".equals(path)) {
                requireAdmin(auth);
                Path manifest = state.storage.exportRepositoryFiles(Path.of("storage", "exports", "repository"));
                writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"manifest\":\"" + json(manifest.toString())
                        + "\",\"manifestHash\":\"" + state.storage.fileHash(manifest) + "\"}");
            } else if ("GET".equals(method) && "/api/storage/status".equals(path)) {
                requireAdmin(auth);
                writeJson(exchange, 200, "{\"code\":\"SUCCESS\",\"mode\":\"memory+json-snapshot\",\"users\":"
                        + state.users.findAll().size() + ",\"dataObjects\":" + state.dataRepository.findAll().size()
                        + ",\"grants\":" + state.grants.findAll().size() + ",\"packages\":"
                        + state.packages.findAll().size() + "}");
            } else {
                writeJson(exchange, 404, errorJson(ErrorCode.INVALID_REQUEST.name(), "unknown endpoint", requestId));
            }
        } catch (ReKeyShareException e) {
            if (e.code() == ErrorCode.UNAUTHENTICATED || e.code() == ErrorCode.ACCESS_DENIED) {
                state.rateLimiter.recordFailure(remote);
            }
            writeJson(exchange, httpStatus(e.code()), errorJson(e.code().name(), e.getMessage(), requestId));
        } catch (IllegalArgumentException e) {
            writeJson(exchange, 400, errorJson(ErrorCode.INVALID_REQUEST.name(), e.getMessage(), requestId));
        } catch (Exception e) {
            writeJson(exchange, 500, errorJson("INTERNAL_ERROR", "internal server error", requestId));
        }
    }

    private static void createUser(HttpExchange exchange, ApiState state, Map<String, String> body) throws IOException {
        String userId = body.getOrDefault("userId", body.getOrDefault("username", "user-" + state.users.findAll().size()));
        AlgorithmType algorithm = state.registry.parse(body.get("algorithm"),
                state.profile.demoFeaturesEnabled() ? AlgorithmType.RSA_PRE : AlgorithmType.SECURE_ENVELOPE);
        requireAlgorithmForProfile(state, algorithm);
        UserRole role = parseRole(body.get("role"), defaultRole(userId));
        User user = state.profile.demoFeaturesEnabled()
                ? state.userService(algorithm).createUser(userId, role)
                : state.userService(algorithm).registerPublicOnlyUser(userId, role);
        state.keys(algorithm).registerActiveKey(user);
        String token = state.tokens.issue(user);
        SchemeDescriptor descriptor = descriptorFor(algorithm);
        writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"userId\":\"" + json(user.userId())
                + "\",\"role\":\"" + user.role() + "\",\"algorithm\":\"" + algorithm
                + "\",\"algorithmSuite\":\"" + descriptor.schemeId()
                + "\",\"securityLevel\":\"" + descriptor.securityLevel()
                + "\",\"securityNotice\":\"" + descriptor.proofStatus()
                + "\",\"token\":\"" + token + "\"}");
    }

    private static void login(HttpExchange exchange, ApiState state, Map<String, String> body) throws IOException {
        String userId = body.get("userId");
        User user = requireUser(state, userId);
        writeJson(exchange, 200, "{\"code\":\"SUCCESS\",\"userId\":\"" + json(user.userId())
                + "\",\"role\":\"" + user.role() + "\",\"token\":\"" + state.tokens.issue(user) + "\"}");
    }

    private static void createKey(HttpExchange exchange, ApiState state, DemoTokenService.AuthenticatedActor actor,
                                  String userId) throws IOException {
        if (!actor.userId().equals(userId) && actor.role() != UserRole.ADMIN) {
            throw new ReKeyShareException(ErrorCode.ACCESS_DENIED, "only key owner or admin can register key metadata");
        }
        User user = state.users.findById(userId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.USER_NOT_FOUND, "user not found"));
        var key = state.keys(state.algorithmForUser(user)).registerActiveKey(user);
        writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"keyId\":\"" + key.keyId() + "\",\"version\":" + key.version() + "}");
    }

    private static void rotateUserKey(HttpExchange exchange, ApiState state, String actor, String userId) throws IOException {
        if (!actor.equals(userId) && !"admin".equalsIgnoreCase(actor)) {
            throw new ReKeyShareException(ErrorCode.ACCESS_DENIED, "only key owner or admin can rotate user key");
        }
        User current = requireUser(state, userId);
        AlgorithmType algorithm = state.algorithmForUser(current);
        User rotated = state.userService(algorithm).rotateUserKey(current);
        var key = state.keys(algorithm).rotateKey(rotated);
        writeJson(exchange, 200, "{\"code\":\"SUCCESS\",\"userId\":\"" + json(rotated.userId())
                + "\",\"keyId\":\"" + key.keyId() + "\",\"version\":" + key.version()
                + ",\"fingerprint\":\"" + key.fingerprint() + "\"}");
    }

    private static void uploadData(HttpExchange exchange, ApiState state, String actor, Map<String, String> body) throws IOException {
        User owner = requireUser(state, actor);
        AlgorithmType requested = state.registry.parse(body.get("algorithm"), state.algorithmForUser(owner));
        if (requested != state.algorithmForUser(owner)) {
            throw new ReKeyShareException(ErrorCode.ALGORITHM_MISMATCH, "requested algorithm does not match owner key");
        }
        byte[] plaintextBytes = body.containsKey("plaintextBase64")
                ? Base64.getDecoder().decode(body.get("plaintextBase64"))
                : body.getOrDefault("plaintext", "api upload plaintext").getBytes(StandardCharsets.UTF_8);
        String fileName = body.getOrDefault("fileName", "api-upload.txt");
        EncryptedDataPackage data = state.data(requested).upload(new DataSecurityService.UploadDataCommand(
                owner, plaintextBytes, fileName, body.getOrDefault("contentType", "text/plain")));
        writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"dataId\":\"" + data.dataId() + "\",\"contentKeyVersion\":" + data.contentKeyVersion() + "}");
    }

    private static void uploadEncryptedData(HttpExchange exchange, ApiState state, String actor, Map<String, String> body) throws IOException {
        User owner = requireUser(state, actor);
        AlgorithmType requested = state.registry.parse(body.get("algorithm"), state.algorithmForUser(owner));
        requireAlgorithmForProfile(state, requested);
        if (requested != state.algorithmForUser(owner)) {
            throw new ReKeyShareException(ErrorCode.ALGORITHM_MISMATCH, "requested algorithm does not match owner key");
        }
        String dataId = body.getOrDefault("dataId", UUID.randomUUID().toString());
        int contentKeyVersion = Integer.parseInt(body.getOrDefault("contentKeyVersion", "1"));
        String ownerKeyId = body.getOrDefault("ownerKeyId", "demo-key-" + owner.userId());
        String policyHash = body.getOrDefault("policyHash", "OWNER_UPLOAD");
        CapsuleContext context = new CapsuleContext(dataId, owner.userId(), owner.userId(),
                requested, ownerKeyId, contentKeyVersion, policyHash,
                body.getOrDefault("tenantId", "tenant-default"),
                body.getOrDefault("grantId", "OWNER_UPLOAD"),
                descriptorFor(requested).schemeId(),
                body.getOrDefault("proofIssuerId", ""),
                body.getOrDefault("operation", "OWNER_UPLOAD"));
        byte[] aad = body.containsKey("aad") ? b64decode(body.get("aad")) : com.example.pre.util.AadBuilder.build(context);
        EncryptedKeyCapsule capsule = new EncryptedKeyCapsule(
                requested,
                b64decode(body.get("capsuleHeader")),
                b64decode(body.get("wrappedKey")),
                b64decode(body.get("keyNonce"))
        ).bindContext(ownerKeyId, contentKeyVersion,
                body.getOrDefault("aadHash", com.example.pre.crypto.hash.Hash.sha256Hex(aad)),
                body.getOrDefault("contextHash", com.example.pre.crypto.hash.Hash.sha256Hex(aad)),
                body.getOrDefault("parameterSpec", requested.name() + "-client-upload"));
        EncryptedDataPackage data = state.data(requested).uploadEncrypted(new DataSecurityService.UploadEncryptedCommand(
                owner,
                b64decode(body.get("encryptedContent")),
                b64decode(body.get("contentNonce")),
                aad,
                capsule,
                context,
                Long.parseLong(body.getOrDefault("originalSize", "-1")),
                body.getOrDefault("fileName", "client-encrypted.bin"),
                body.getOrDefault("contentType", "application/octet-stream")
        ));
        SchemeDescriptor descriptor = descriptorFor(requested);
        writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"dataId\":\"" + data.dataId()
                + "\",\"contentKeyVersion\":" + data.contentKeyVersion()
                + ",\"ciphertextHash\":\"" + data.ciphertextHash()
                + "\",\"algorithmSuite\":\"" + descriptor.schemeId()
                + "\",\"securityLevel\":\"" + descriptor.securityLevel()
                + "\",\"securityNotice\":\"" + descriptor.proofStatus() + "\"}");
    }

    private static void getData(HttpExchange exchange, ApiState state, String actor, String dataId) throws IOException {
        state.objectAuth.assertCanReadData(actor, dataId);
        EncryptedDataPackage data = state.dataRepository.findById(dataId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.DATA_NOT_FOUND, "data not found"));
        writeJson(exchange, 200, "{\"code\":\"SUCCESS\",\"dataId\":\"" + data.dataId() + "\",\"ownerId\":\"" + data.ownerId()
                + "\",\"ciphertextHash\":\"" + data.ciphertextHash() + "\"}");
    }

    private static void createGrant(HttpExchange exchange, ApiState state, String actor, Map<String, String> body) throws IOException {
        requireDemoFeature(state, "baseline grant creation");
        String dataId = body.get("dataId");
        String recipientId = body.get("recipientId");
        state.objectAuth.assertCanCreateGrant(actor, dataId);
        User owner = requireUser(state, actor);
        User recipient = requireUser(state, recipientId);
        EncryptedDataPackage data = state.dataRepository.findById(dataId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.DATA_NOT_FOUND, "data not found"));
        AccessPolicy policy = policyFromBody(body);
        ShareGrant grant = state.authorization(data.algorithm()).createGrant(owner, recipient, data, policy);
        writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"grantId\":\"" + grant.grantId() + "\",\"policyHash\":\"" + grant.policyHash() + "\"}");
    }

    private static void createEccGrant(HttpExchange exchange, ApiState state, String actor, Map<String, String> body) throws IOException {
        requireDemoFeature(state, "ECC baseline grant creation");
        String dataId = body.get("dataId");
        String recipientId = body.get("recipientId");
        String sessionId = body.get("sessionId");
        state.objectAuth.assertCanCreateGrant(actor, dataId);
        User owner = requireUser(state, actor);
        User recipient = requireUser(state, recipientId);
        EncryptedDataPackage data = state.dataRepository.findById(dataId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.DATA_NOT_FOUND, "data not found"));
        AccessPolicy policy = policyFromBody(body);
        ShareGrant grant = state.authorization(AlgorithmType.ECC_PRE)
                .createGrantFromVerifiedRecipientShare(owner, recipient, data, policy, state.eccShares, sessionId);
        writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"grantId\":\"" + grant.grantId()
                + "\",\"sessionId\":\"" + json(sessionId) + "\",\"policyHash\":\"" + grant.policyHash() + "\"}");
    }

    private static AccessPolicy policyFromBody(Map<String, String> body) {
        int maxAccessCount = Integer.parseInt(body.getOrDefault("maxAccessCount", "5"));
        int maxReEncryptCount = Integer.parseInt(body.getOrDefault("maxReEncryptCount", String.valueOf(maxAccessCount)));
        int maxDownloadCount = Integer.parseInt(body.getOrDefault("maxDownloadCount", String.valueOf(maxAccessCount)));
        int maxDecryptCount = Integer.parseInt(body.getOrDefault("maxDecryptCount", String.valueOf(maxAccessCount)));
        long expiresInSeconds = Long.parseLong(body.getOrDefault("expiresInSeconds", "604800"));
        return new AccessPolicy(
                Boolean.parseBoolean(body.getOrDefault("allowPreview", "true")),
                Boolean.parseBoolean(body.getOrDefault("allowDownload", "true")),
                Boolean.parseBoolean(body.getOrDefault("allowReshare", "false")),
                maxAccessCount,
                maxReEncryptCount,
                maxDownloadCount,
                maxDecryptCount,
                Instant.now().plus(expiresInSeconds, ChronoUnit.SECONDS),
                body.getOrDefault("purpose", "api-demo"),
                body.getOrDefault("allowedActions", "download,decrypt")
        );
    }

    private static void createReKeySession(HttpExchange exchange, ApiState state, String actor, Map<String, String> body) throws IOException {
        requireDemoFeature(state, "ECC baseline rekey session");
        String dataId = body.get("dataId");
        String recipientId = body.get("recipientId");
        state.objectAuth.assertCanCreateGrant(actor, dataId);
        ReKeySession session = state.eccShares.createSession(dataId, actor, recipientId);
        writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"sessionId\":\"" + session.sessionId()
                + "\",\"challenge\":\"" + session.challenge() + "\",\"expiresAt\":\"" + session.expiresAt() + "\"}");
    }

    private static void submitRecipientShare(HttpExchange exchange, ApiState state, String actor, String sessionId, Map<String, String> body) throws IOException {
        ReKeySession session = state.eccShares.requireSession(sessionId);
        if (!session.recipientId().equals(actor)) {
            throw new ReKeyShareException(ErrorCode.ACCESS_DENIED, "only session recipient can submit share");
        }
        RecipientReKeyShare share = new RecipientReKeyShare(new BigInteger(body.get("recipientShare")));
        RecipientShareSubmission submission = new RecipientShareSubmission(
                sessionId,
                session.dataId(),
                session.ownerId(),
                actor,
                body.getOrDefault("challenge", session.challenge()),
                share,
                body.getOrDefault("recipientShareHash", DemoRecipientShareSignature.shareHash(share)),
                body.get("signature"),
                Instant.now()
        );
        state.eccShares.submitRecipientShare(submission);
        writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"sessionId\":\"" + sessionId + "\",\"status\":\"SHARE_SUBMITTED\"}");
    }

    private static void submitRecipientShareDemo(HttpExchange exchange, ApiState state, String actor, String sessionId) throws IOException {
        ReKeySession session = state.eccShares.requireSession(sessionId);
        if (!session.recipientId().equals(actor)) {
            throw new ReKeyShareException(ErrorCode.ACCESS_DENIED, "only session recipient can submit share");
        }
        User recipient = requireUser(state, actor);
        RecipientReKeyShare share = DemoPrivateKeyStore.createEccRecipientShareLocally(recipient, session.cryptoContext());
        RecipientShareSubmission submission = new RecipientShareSubmission(
                sessionId,
                session.dataId(),
                session.ownerId(),
                actor,
                session.challenge(),
                share,
                DemoRecipientShareSignature.shareHash(share),
                DemoRecipientShareSignature.sign(session, share),
                Instant.now()
        );
        state.eccShares.submitRecipientShare(submission);
        writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"sessionId\":\"" + sessionId
                + "\",\"status\":\"SHARE_SUBMITTED\",\"shareHash\":\"" + submission.recipientShareHash() + "\"}");
    }

    private static void revokeGrant(HttpExchange exchange, ApiState state, String actor, String grantId) throws IOException {
        ShareGrant existing = state.grants.findById(grantId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.GRANT_NOT_FOUND, "grant not found"));
        ShareGrant grant = state.revocation(existing.algorithm()).revokeGrant(actor, grantId);
        writeJson(exchange, 200, "{\"code\":\"SUCCESS\",\"grantId\":\"" + grant.grantId() + "\",\"status\":\"" + grant.status() + "\"}");
    }

    private static void proxyReEncrypt(HttpExchange exchange, ApiState state, SecurityContext actor, Map<String, String> body) throws IOException {
        requireDemoFeature(state, "baseline proxy transformation");
        ShareGrant grant = state.grants.findById(body.get("grantId"))
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.GRANT_NOT_FOUND, "grant not found"));
        state.proxyNodes.assertCanProxy(actor, grant.algorithm());
        ReEncryptedPackage dataPackage = state.proxy(grant.algorithm()).reEncrypt(actor, body.get("grantId"));
        writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"packageId\":\"" + dataPackage.packageId() + "\",\"grantId\":\"" + dataPackage.grantId() + "\"}");
    }

    private static void registerProxyNode(HttpExchange exchange, ApiState state, String actor, Map<String, String> body) throws IOException {
        String proxyId = body.getOrDefault("proxyId", "proxy");
        String fingerprint = body.getOrDefault("certificateFingerprint", "demo-service-token");
        String tenants = body.getOrDefault("allowedTenantIds", "*");
        Set<AlgorithmType> allowedSchemes = java.util.Arrays.stream(
                        body.getOrDefault("allowedSchemeIds", "RSA_PRE,ECC_PRE,SECURE_ENVELOPE").split(","))
                .map(String::trim)
                .map(String::toUpperCase)
                .map(AlgorithmType::valueOf)
                .collect(java.util.stream.Collectors.toSet());
        long quota = Long.parseLong(body.getOrDefault("quota", String.valueOf(Long.MAX_VALUE)));
        state.proxyNodes.register(actor, proxyId, fingerprint, Set.of(tenants.split(",")), allowedSchemes, quota);
        writeJson(exchange, 201, "{\"code\":\"SUCCESS\",\"proxyId\":\"" + json(proxyId) + "\",\"status\":\"ACTIVE\"}");
    }

    private static void revokeProxyNode(HttpExchange exchange, ApiState state, String actor, String proxyId) throws IOException {
        state.proxyNodes.revoke(actor, proxyId);
        writeJson(exchange, 200, "{\"code\":\"SUCCESS\",\"proxyId\":\"" + json(proxyId) + "\",\"status\":\"REVOKED\"}");
    }

    private static void getSharedPackage(HttpExchange exchange, ApiState state, String actor, String packageId) throws IOException {
        ReEncryptedPackage dataPackage;
        ShareGrant grant;
        SharedPackageV2 v2;
        synchronized (state.grants) {
            dataPackage = state.objectAuth.assertCanDownloadPackage(actor, packageId);
            grant = state.grants.findById(dataPackage.grantId())
                    .orElseThrow(() -> new ReKeyShareException(ErrorCode.GRANT_NOT_FOUND, "grant not found"));
            v2 = SharedPackageV2.issue(dataPackage, descriptorFor(dataPackage.algorithm()), grant.expiresAt());
            try {
                new PackageVerifier().verifyFormalPackage(v2, grant, state.conversionProofs, Instant.now());
            } catch (ReKeyShareException e) {
                state.audit.record(actor, "CONVERSION_PROOF_VERIFY_FAILED", packageId, false, e.code().name());
                throw e;
            }
            state.grants.save(grant.incrementDownload());
        }
        state.audit.record(actor, "DOWNLOAD_PACKAGE", packageId, true, dataPackage.grantId());
        writeJson(exchange, 200, "{\"code\":\"SUCCESS\",\"packageVersion\":\"" + v2.packageVersion()
                + "\",\"schemeId\":\"" + v2.schemeId()
                + "\",\"algorithmSuite\":\"" + v2.schemeId()
                + "\",\"securityLevel\":\"" + descriptorFor(dataPackage.algorithm()).securityLevel()
                + "\",\"securityNotice\":\"" + v2.proofStatus()
                + "\",\"parameterSpec\":\"" + json(v2.parameterSpec())
                + "\",\"proofStatus\":\"" + v2.proofStatus()
                + "\",\"conversionProofDigest\":\"" + com.example.pre.service.ConversionProofService.digest(dataPackage.conversionProof())
                + "\",\"conversionProofProxyId\":\"" + json(dataPackage.conversionProof().proxyId())
                + "\",\"packageId\":\"" + packageId
                + "\",\"dataId\":\"" + dataPackage.dataId()
                + "\",\"ownerId\":\"" + dataPackage.ownerId()
                + "\",\"recipientId\":\"" + dataPackage.recipientId()
                + "\",\"algorithm\":\"" + dataPackage.algorithm()
                + "\",\"contentKeyVersion\":" + dataPackage.contentKeyVersion()
                + ",\"ciphertext\":\"" + b64(dataPackage.encryptedContent())
                + "\",\"nonce\":\"" + b64(dataPackage.contentNonce())
                + "\",\"aad\":\"" + b64(dataPackage.aad())
                + "\",\"grantAad\":\"" + b64(dataPackage.grantAad())
                + "\",\"reEncryptedCapsule\":{\"capsuleId\":\"" + dataPackage.reEncryptedCapsule().capsuleId()
                + "\",\"algorithm\":\"" + dataPackage.reEncryptedCapsule().algorithm()
                + "\",\"parameterSpec\":\"" + dataPackage.reEncryptedCapsule().parameterSpec()
                + "\",\"header\":\"" + b64(dataPackage.reEncryptedCapsule().header())
                + "\",\"wrappedKey\":\"" + b64(dataPackage.reEncryptedCapsule().wrappedKey())
                + "\",\"keyNonce\":\"" + b64(dataPackage.reEncryptedCapsule().keyNonce())
                + "\",\"aadHash\":\"" + dataPackage.reEncryptedCapsule().aadHash()
                + "\",\"contextHash\":\"" + dataPackage.reEncryptedCapsule().contextHash() + "\"}"
                + ",\"ciphertextStoragePath\":\"" + json(dataPackage.ciphertextStoragePath())
                + "\",\"policyHash\":\"" + dataPackage.policyHash()
                + "\",\"grantPolicyHash\":\"" + dataPackage.grantPolicyHash()
                + "\",\"grantContextHash\":\"" + dataPackage.grantContextHash()
                + "\",\"manifestHash\":\"" + v2.manifest().manifestHash()
                + "\",\"ciphertextHash\":\"" + v2.manifest().ciphertextHash()
                + "\",\"aadHash\":\"" + v2.manifest().aadHash()
                + "\",\"capsuleHash\":\"" + v2.manifest().capsuleHash()
                + "\",\"status\":\"" + dataPackage.status() + "\"}");
    }

    private static void demoDecryptSharedPackage(HttpExchange exchange, ApiState state, String actor, String packageId) throws IOException {
        requireDemoFeature(state, "/api/demo/shared-packages/{packageId}/decrypt");
        ReEncryptedPackage dataPackage = state.objectAuth.assertCanDecryptPackage(actor, packageId);
        ShareGrant grant = state.grants.findById(dataPackage.grantId())
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.GRANT_NOT_FOUND, "grant not found"));
        User recipient = requireUser(state, actor);
        byte[] plaintext = state.data(dataPackage.algorithm()).decryptReEncrypted(recipient, dataPackage);
        state.grants.save(grant.incrementDecrypt());
        state.audit.record(actor, "DEMO_DECRYPT_SHARED", packageId, true, dataPackage.grantId());
        writeJson(exchange, 200, "{\"code\":\"SUCCESS\",\"packageId\":\"" + packageId + "\",\"plaintext\":\""
                + json(new String(plaintext, StandardCharsets.UTF_8)) + "\"}");
    }

    private static void auditEvents(HttpExchange exchange, ApiState state) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"count\":").append(state.audit.events().size()).append(",\"events\":[");
        for (int i = 0; i < state.audit.events().size(); i++) {
            AuditEvent event = state.audit.events().get(i);
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"eventId\":\"").append(event.eventId()).append("\",\"action\":\"").append(event.action())
                    .append("\",\"actor\":\"").append(json(event.actor())).append("\",\"target\":\"")
                    .append(json(event.target())).append("\",\"success\":").append(event.success()).append('}');
        }
        sb.append("]}");
        writeJson(exchange, 200, sb.toString());
    }

    private static void auditVerify(HttpExchange exchange, ApiState state) throws IOException {
        AuditService.AuditVerificationResult before = state.audit.verifyChain();
        state.audit.record("audit", "AUDIT_VERIFY", "audit-chain", before.valid(), "checkedEvents=" + before.checkedEvents());
        AuditService.AuditVerificationResult after = state.audit.verifyChain();
        writeJson(exchange, 200, "{"
                + "\"valid\":" + before.valid() + ","
                + "\"checkedEvents\":" + before.checkedEvents() + ","
                + "\"brokenAt\":" + (before.brokenAt() == null ? "null" : before.brokenAt()) + ","
                + "\"rootBeforeVerify\":\"" + before.rootHash() + "\","
                + "\"rootAfterVerify\":\"" + after.rootHash() + "\""
                + "}");
    }

    private static User requireUser(ApiState state, String userId) {
        return state.users.findById(userId)
                .orElseThrow(() -> new ReKeyShareException(ErrorCode.USER_NOT_FOUND, "user not found: " + userId));
    }

    private static DemoTokenService.AuthenticatedActor actor(HttpExchange exchange, Map<String, String> body, ApiState state) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            return state.tokens.verify(authorization.substring("Bearer ".length()).trim());
        }
        if (state.legacyActorHeaderEnabled) {
            String header = exchange.getRequestHeaders().getFirst("X-Actor-Id");
            if (header != null && !header.isBlank()) {
                User user = state.users.findById(header).orElse(null);
                long now = Instant.now().getEpochSecond();
                return new DemoTokenService.AuthenticatedActor(header, user == null ? defaultRole(header) : user.role(), "legacy", "legacy", now, now + 300);
            }
        }
        String fallback = body.getOrDefault("actorId", body.getOrDefault("userId", ""));
        if (!fallback.isBlank() && state.legacyActorHeaderEnabled) {
            User user = state.users.findById(fallback).orElse(null);
            long now = Instant.now().getEpochSecond();
            return new DemoTokenService.AuthenticatedActor(fallback, user == null ? defaultRole(fallback) : user.role(), "legacy", "legacy", now, now + 300);
        }
        throw new ReKeyShareException(ErrorCode.UNAUTHENTICATED, "signed bearer token is required");
    }

    private static boolean publicEndpoint(String method, String path) {
        return ("GET".equals(method) && "/".equals(path))
                || ("GET".equals(method) && "/openapi.json".equals(path))
                || ("POST".equals(method) && "/api/users".equals(path))
                || ("POST".equals(method) && "/api/auth/login".equals(path));
    }

    private static void requireDemoFeature(ApiState state, String feature) {
        if (!state.profile.demoFeaturesEnabled()) {
            throw new ReKeyShareException(ErrorCode.DEMO_ONLY_API_DISABLED, "demo feature is disabled in production profile: " + feature);
        }
    }

    private static IdempotencyService.Decision beginIdempotency(HttpExchange exchange, ApiState state, String method,
                                                                 String path, String actor, Map<String, String> body) {
        if (!"POST".equals(method)) {
            return null;
        }
        String key = exchange.getRequestHeaders().getFirst("Idempotency-Key");
        if (key == null || key.isBlank()) {
            return null;
        }
        return state.idempotency.begin(key, actor, method, path, body.toString());
    }

    private static void requireAlgorithmForProfile(ApiState state, AlgorithmType algorithm) {
        if (!state.profile.demoFeaturesEnabled() && algorithm != AlgorithmType.SECURE_ENVELOPE) {
            throw new ReKeyShareException(ErrorCode.CRYPTO_PROFILE_NOT_ALLOWED,
                    "production profile permits only SECURE_ENVELOPE");
        }
    }

    private static void enforceContentType(HttpExchange exchange, String method) {
        if (!"POST".equals(method)) {
            return;
        }
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || contentType.isBlank()) {
            throw new ReKeyShareException(ErrorCode.INVALID_REQUEST, "Content-Type is required for POST requests");
        }
        String normalized = contentType.toLowerCase(java.util.Locale.ROOT);
        if (!normalized.startsWith("application/json")
                && !normalized.startsWith("application/x-www-form-urlencoded")) {
            throw new ReKeyShareException(ErrorCode.INVALID_REQUEST, "unsupported Content-Type");
        }
    }

    private static UserRole parseRole(String value, UserRole fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return UserRole.valueOf(value.trim().toUpperCase());
    }

    private static UserRole defaultRole(String userId) {
        if ("proxy".equalsIgnoreCase(userId) || "ProxyNode".equalsIgnoreCase(userId)) {
            return UserRole.PROXY;
        }
        if ("admin".equalsIgnoreCase(userId)) {
            return UserRole.ADMIN;
        }
        return UserRole.RECIPIENT;
    }

    private static void requireRole(DemoTokenService.AuthenticatedActor actor, UserRole role) {
        if (actor.role() != role && actor.role() != UserRole.ADMIN) {
            throw new ReKeyShareException(ErrorCode.ACCESS_DENIED, "required role: " + role);
        }
    }

    private static void requireAdmin(DemoTokenService.AuthenticatedActor actor) {
        requireRole(actor, UserRole.ADMIN);
    }

    private static Map<String, String> readFields(HttpExchange exchange) throws IOException {
        Map<String, String> values = parseQuery(exchange.getRequestURI().getRawQuery());
        if (!"GET".equals(exchange.getRequestMethod())) {
            byte[] bodyBytes = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
            if (bodyBytes.length > MAX_BODY_BYTES) {
                throw new ReKeyShareException(ErrorCode.PAYLOAD_TOO_LARGE, "request body too large");
            }
            String body = new String(bodyBytes, StandardCharsets.UTF_8).trim();
            values.putAll(parseBody(body));
        }
        return values;
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> out = new LinkedHashMap<>();
        if (query == null || query.isBlank()) {
            return out;
        }
        for (String part : query.split("&")) {
            int idx = part.indexOf('=');
            if (idx > 0) {
                out.put(decode(part.substring(0, idx)), decode(part.substring(idx + 1)));
            }
        }
        return out;
    }

    private static Map<String, String> parseBody(String body) {
        if (body.startsWith("{") || body.endsWith("}")) {
            return parseJsonObject(body);
        }
        return parseQuery(body);
    }

    private static Map<String, String> parseJsonObject(String body) {
        return JsonFields.parseObject(body);
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String segment(String path, int index) {
        String[] parts = path.split("/");
        return parts[index];
    }

    private static void writeJson(HttpExchange exchange, int status, String body) throws IOException {
        Object pending = exchange.getAttribute("rekeyshare.idempotency");
        if (pending instanceof PendingResponse response) {
            response.service().complete(response.pending(), status, body);
            exchange.setAttribute("rekeyshare.idempotency", null);
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static int httpStatus(ErrorCode code) {
        return switch (code) {
            case DATA_NOT_FOUND, USER_NOT_FOUND, GRANT_NOT_FOUND, PACKAGE_NOT_FOUND -> 404;
            case UNAUTHENTICATED -> 401;
            case RATE_LIMITED -> 429;
            case PAYLOAD_TOO_LARGE -> 413;
            case INVALID_REQUEST, ALGORITHM_MISMATCH, CAPSULE_TAMPERED, CIPHERTEXT_TAMPERED, PACKAGE_INVALID,
                    INVALID_RECIPIENT_SHARE, INVALID_REKEY_SESSION, CRYPTO_CONTEXT_MISMATCH -> 400;
            default -> 403;
        };
    }

    private static String json(String value) {
        return Optional.ofNullable(value).orElse("").replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String errorJson(String code, String message, String requestId) {
        String eventId = "err-" + UUID.randomUUID();
        return "{\"success\":false,\"errorCode\":\"" + json(code) + "\",\"code\":\"" + json(code)
                + "\",\"message\":\"" + json(message) + "\",\"traceId\":\"" + json(requestId)
                + "\",\"requestId\":\"" + json(requestId) + "\",\"eventId\":\"" + eventId
                + "\",\"timestamp\":\"" + Instant.now() + "\"}";
    }

    private static String b64(byte[] value) {
        return Base64.getEncoder().encodeToString(value == null ? new byte[0] : value);
    }

    private static byte[] b64decode(String value) {
        if (value == null || value.isBlank()) {
            throw new ReKeyShareException(ErrorCode.INVALID_REQUEST, "missing base64 field");
        }
        return Base64.getDecoder().decode(value);
    }

    private static SchemeDescriptor descriptorFor(AlgorithmType algorithm) {
        return switch (algorithm) {
            case RSA_PRE -> new SchemeDescriptor("RSA_PRE_BASELINE", "RSA common-modulus transformation",
                    "EXPERIMENTAL", "RSA-PRE-baseline", true, true, false,
                    "NOT_PRODUCTION_REVIEWED", "IMPLEMENTED");
            case ECC_PRE -> new SchemeDescriptor("ECC_PRE_BASELINE", "Experimental P-256 transformation",
                    "EXPERIMENTAL", "ECC-PRE-P-256-demo", true, true, false,
                    "NOT_PRODUCTION_REVIEWED", "IMPLEMENTED");
            case SECURE_ENVELOPE -> new SchemeDescriptor("SECURE_ENVELOPE_V1", "ECDH-KEM envelope",
                    "128-bit", "P-256/HKDF-SHA256/AES-256-GCM", false, false, false,
                    "JCA_PRIMITIVES_SECURITY_BOUNDARY_DOCUMENTED", "IMPLEMENTED");
        };
    }

    private static String openApiJson(RuntimeProfile profile) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"openapi\":\"3.0.3\",")
                .append("\"info\":{\"title\":\"ReKeyShare API\",\"version\":\"1.0.0\"},")
                .append("\"security\":[{\"bearerAuth\":[]}],")
                .append("\"paths\":{");
        appendPath(sb, "/api/users", "post", false, "Create user and issue demo token");
        appendPath(sb, "/api/auth/login", "post", false, "Issue signed demo token");
        appendPath(sb, "/api/users/{userId}/keys", "post", true, "Register current public key metadata");
        if (profile.demoFeaturesEnabled()) {
            appendPath(sb, "/api/users/{userId}/keys/rotate", "post", true, "Demo-only service-side keypair rotation");
        }
        if (profile.demoFeaturesEnabled()) {
            appendPath(sb, "/api/data/upload", "post", true, "Demo-only plaintext upload fixture");
        }
        appendPath(sb, "/api/data/upload-encrypted", "post", true, "Upload client-side encrypted content and PRE capsule");
        appendPath(sb, "/api/data/{dataId}", "get", true, "Read data metadata with object authorization");
        appendPath(sb, "/api/grants/{grantId}/revoke", "post", true, "Revoke grant");
        if (profile.demoFeaturesEnabled()) {
            appendPath(sb, "/api/grants", "post", true, "Demo RSA baseline grant");
            appendPath(sb, "/api/grants/ecc", "post", true, "Demo ECC baseline grant from verified recipient share");
            appendPath(sb, "/api/rekey-sessions", "post", true, "Demo ECC recipient-share session");
            appendPath(sb, "/api/rekey-sessions/{sessionId}/recipient-share", "post", true, "Demo signed ECC recipient share");
            appendPath(sb, "/api/proxy/re-encrypt", "post", true, "Demo baseline proxy capsule transform");
        }
        appendPath(sb, "/api/proxy-nodes", "post", true, "Register proxy node");
        appendPath(sb, "/api/proxy-nodes/{proxyId}/revoke", "post", true, "Revoke proxy node");
        appendPath(sb, "/api/shared-packages/{packageId}", "get", true, "Download encrypted package metadata");
        if (profile.demoFeaturesEnabled()) {
            appendPath(sb, "/api/demo/shared-packages/{packageId}/decrypt", "get", true, "Demo-only plaintext verification");
        }
        appendPath(sb, "/api/audit/events", "get", true, "List audit events");
        appendPath(sb, "/api/audit/verify", "get", true, "Verify audit chain");
        appendPath(sb, "/api/audit/proof", "get", true, "Export audit chain/Merkle proof");
        appendPath(sb, "/api/benchmark/run", "post", true, "Run benchmark");
        appendPath(sb, "/api/benchmark/results", "get", true, "Read benchmark result location");
        appendPath(sb, "/api/benchmark/summary", "get", true, "Read structured benchmark summary");
        appendPath(sb, "/api/storage/status", "get", true, "Read storage mode");
        appendPath(sb, "/api/storage/export", "post", true, "Export JSON snapshot");
        appendPath(sb, "/api/storage/import-check", "post", true, "Verify JSON snapshot hash");
        appendPath(sb, "/api/storage/export-index", "post", true, "Export repository-like JSON files and manifest");
        if (sb.charAt(sb.length() - 1) == ',') {
            sb.setLength(sb.length() - 1);
        }
        sb.append("},\"components\":{\"securitySchemes\":{\"bearerAuth\":{\"type\":\"http\",\"scheme\":\"bearer\"}},")
                .append("\"schemas\":{")
                .append("\"Error\":{\"type\":\"object\",\"properties\":{\"success\":{\"type\":\"boolean\"},\"code\":{\"type\":\"string\"},\"message\":{\"type\":\"string\"},\"requestId\":{\"type\":\"string\"}}},")
                .append("\"CreateUserRequest\":{\"type\":\"object\",\"properties\":{\"userId\":{\"type\":\"string\"},\"role\":{\"type\":\"string\"},\"algorithm\":{\"type\":\"string\",\"enum\":[\"SECURE_ENVELOPE\",\"RSA_PRE\",\"ECC_PRE\"]}}},")
                .append("\"UploadDataRequest\":{\"type\":\"object\",\"properties\":{\"algorithm\":{\"type\":\"string\",\"enum\":[\"RSA_PRE\",\"ECC_PRE\"]},\"fileName\":{\"type\":\"string\"},\"contentType\":{\"type\":\"string\"},\"plaintext\":{\"type\":\"string\",\"description\":\"demo-only\"},\"plaintextBase64\":{\"type\":\"string\",\"description\":\"demo-only\"}}},")
                .append("\"UploadEncryptedRequest\":{\"type\":\"object\",\"required\":[\"encryptedContent\",\"contentNonce\",\"capsuleHeader\",\"wrappedKey\",\"keyNonce\"],\"properties\":{\"algorithm\":{\"type\":\"string\",\"enum\":[\"SECURE_ENVELOPE\",\"RSA_PRE\",\"ECC_PRE\"]},\"dataId\":{\"type\":\"string\"},\"encryptedContent\":{\"type\":\"string\",\"format\":\"byte\"},\"contentNonce\":{\"type\":\"string\",\"format\":\"byte\"},\"aad\":{\"type\":\"string\",\"format\":\"byte\"},\"capsuleHeader\":{\"type\":\"string\",\"format\":\"byte\"},\"wrappedKey\":{\"type\":\"string\",\"format\":\"byte\"},\"keyNonce\":{\"type\":\"string\",\"format\":\"byte\"}}},")
                .append("\"CreateGrantRequest\":{\"type\":\"object\",\"properties\":{\"dataId\":{\"type\":\"string\"},\"recipientId\":{\"type\":\"string\"},\"maxAccessCount\":{\"type\":\"integer\"},\"expiresInSeconds\":{\"type\":\"integer\"},\"purpose\":{\"type\":\"string\"}}},")
                .append("\"ProxyReEncryptRequest\":{\"type\":\"object\",\"properties\":{\"grantId\":{\"type\":\"string\"}}},")
                .append("\"SharedPackageResponse\":{\"type\":\"object\",\"properties\":{\"packageId\":{\"type\":\"string\"},\"dataId\":{\"type\":\"string\"},\"ownerId\":{\"type\":\"string\"},\"recipientId\":{\"type\":\"string\"},\"algorithm\":{\"type\":\"string\"},\"contentKeyVersion\":{\"type\":\"integer\"},\"ciphertext\":{\"type\":\"string\",\"format\":\"byte\"},\"nonce\":{\"type\":\"string\",\"format\":\"byte\"},\"aad\":{\"type\":\"string\",\"format\":\"byte\"},\"reEncryptedCapsule\":{\"type\":\"object\"},\"grantPolicyHash\":{\"type\":\"string\"},\"grantContextHash\":{\"type\":\"string\"}}}")
                .append("}}}");
        return sb.toString();
    }

    private static void appendPath(StringBuilder sb, String path, String method, boolean secured, String summary) {
        sb.append('"').append(path).append("\":{\"").append(method).append("\":{\"summary\":\"")
                .append(summary).append("\",\"responses\":{\"200\":{\"description\":\"OK\"},")
                .append("\"201\":{\"description\":\"Created\"},\"400\":{\"description\":\"Invalid request\"},")
                .append("\"403\":{\"description\":\"Access denied\"}}");
        if (!secured) {
            sb.append(",\"security\":[]");
        }
        sb.append("}},");
    }

    private record PendingResponse(IdempotencyService service, IdempotencyService.Pending pending) {
    }

    private static final class ApiState {
        final RuntimeProfile profile;
        final SchemeRegistry registry = new SchemeRegistry();
        final CryptoProviderRegistry cryptoProviders = new CryptoProviderRegistry();
        final DemoTokenService tokens = new DemoTokenService("rekeyshare-demo-signing-secret", 3600);
        final InMemoryAuditRepository auditRepository = new InMemoryAuditRepository();
        final InMemoryUserRepository users = new InMemoryUserRepository();
        final InMemoryDataRepository dataRepository = new InMemoryDataRepository();
        final InMemoryGrantRepository grants = new InMemoryGrantRepository();
        final InMemoryReEncryptedPackageRepository packages = new InMemoryReEncryptedPackageRepository();
        final InMemoryKeyRepository keyRepository = new InMemoryKeyRepository();
        final AuditService audit = new AuditService(auditRepository);
        final ObjectAuthorizationService objectAuth = new ObjectAuthorizationService(dataRepository, grants, packages, auditRepository);
        final StorageSnapshotService storage = new StorageSnapshotService(users, dataRepository, grants, packages, auditRepository);
        final EccRecipientShareService eccShares = new EccRecipientShareService();
        final AuditProofService auditProof = new AuditProofService();
        final com.example.pre.service.ConversionProofService conversionProofs = new com.example.pre.service.ConversionProofService();
        final BenchmarkResultService benchmark = new BenchmarkResultService();
        final SimpleRateLimiter rateLimiter = new SimpleRateLimiter(20, 60);
        final IdempotencyService idempotency = new IdempotencyService(Duration.ofHours(24));
        final ProxyNodeService proxyNodes = new ProxyNodeService(auditRepository);
        final boolean legacyActorHeaderEnabled = false;

        ApiState(RuntimeProfile profile) {
            this.profile = profile;
            if (profile == RuntimeProfile.PRODUCTION) {
                cryptoProviders.productionDefault();
            }
            audit.record("system", "API_START", "ReKeyShareApplication", true, "profile=" + profile);
            proxyNodes.register("system", "proxy", "default-service-token", Set.of("*"));
        }

        UserService userService(AlgorithmType algorithm) {
            return new UserService(registry.get(algorithm), users, auditRepository);
        }

        KeyManagementService keys(AlgorithmType algorithm) {
            return new KeyManagementService(registry.get(algorithm), keyRepository, auditRepository);
        }

        DataSecurityService data(AlgorithmType algorithm) {
            return new DataSecurityService(registry.get(algorithm), dataRepository, auditRepository);
        }

        AuthorizationService authorization(AlgorithmType algorithm) {
            return new AuthorizationService(registry.get(algorithm), auditRepository, grants);
        }

        ProxyReEncryptionService proxy(AlgorithmType algorithm) {
            return new ProxyReEncryptionService(registry.get(algorithm), dataRepository, grants, packages, objectAuth,
                    auditRepository, conversionProofs);
        }

        RevocationService revocation(AlgorithmType algorithm) {
            return new RevocationService(registry.get(algorithm), dataRepository, grants, packages, objectAuth, auditRepository);
        }

        AlgorithmType algorithmForUser(User user) {
            return registry.forUser(user).algorithm();
        }
    }

    private static final class SimpleRateLimiter {
        private final int maxFailures;
        private final long windowSeconds;
        private final ConcurrentHashMap<String, ArrayDeque<Long>> failures = new ConcurrentHashMap<>();

        SimpleRateLimiter(int maxFailures, long windowSeconds) {
            this.maxFailures = maxFailures;
            this.windowSeconds = windowSeconds;
        }

        void assertAllowed(String key) {
            ArrayDeque<Long> events = failures.get(key);
            if (events == null) {
                return;
            }
            synchronized (events) {
                prune(events);
                if (events.size() >= maxFailures) {
                    throw new ReKeyShareException(ErrorCode.RATE_LIMITED, "too many failed authentication or authorization attempts");
                }
            }
        }

        void recordFailure(String key) {
            ArrayDeque<Long> events = failures.computeIfAbsent(key, ignored -> new ArrayDeque<>());
            synchronized (events) {
                prune(events);
                events.addLast(Instant.now().getEpochSecond());
            }
        }

        private void prune(ArrayDeque<Long> events) {
            long cutoff = Instant.now().getEpochSecond() - windowSeconds;
            while (!events.isEmpty() && events.peekFirst() < cutoff) {
                events.removeFirst();
            }
        }
    }
}
