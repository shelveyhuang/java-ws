import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.handler.codec.http.websocketx.extensions.compression.WebSocketServerCompressionHandler;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.timeout.IdleStateHandler;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import io.github.cdimascio.dotenv.Dotenv;

public class App {
    
    private static String UUID;
    private static String NEZHA_SERVER;
    private static String NEZHA_PORT;
    private static String NEZHA_KEY;
    private static String DOMAIN;
    private static String SUB_PATH;
    private static String NAME;
    private static String WSPATH;
    private static int PORT;
    private static boolean AUTO_ACCESS;
    private static boolean DEBUG;
    
    private static String PROTOCOL_UUID;
    private static byte[] UUID_BYTES;
    
    private static String currentDomain;
    private static int currentPort = 443;
    private static String tls = "tls";
    private static String isp = "Unknown";
    
    private static final List<String> BLOCKED_DOMAINS = Arrays.asList(
            "speedtest.net", "fast.com", "speedtest.cn", "speed.cloudflare.com", 
            "speedof.me", "testmy.net", "bandwidth.place", "speed.io", 
            "librespeed.org", "speedcheck.org");
    private static final List<String> TLS_PORTS = Arrays.asList(
            "443", "8443", "2096", "2087", "2083", "2053");
    
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private static final Map<String, String> dnsCache = new ConcurrentHashMap<>();
    private static final Map<String, Long> dnsCacheTime = new ConcurrentHashMap<>();
    private static final long DNS_CACHE_TTL = 300000;
    
    private static Process nezhaProcess = null;
    private static boolean SILENT_MODE = true; 
    
    private static void log(String level, String msg) {
        if (SILENT_MODE && !level.equals("INFO")) return;  
        System.out.println(new Date() + " - " + level + " - " + msg);
    }
    
    private static void info(String msg) { log("INFO", msg); }
    private static void error(String msg) { log("ERROR", msg); }
    private static void error(String msg, Throwable t) { 
        log("ERROR", msg);
        if (DEBUG) t.printStackTrace();
    }
    private static void debug(String msg) { if (DEBUG) log("DEBUG", msg); }
    
    private static void loadConfig() {
        Map<String, String> envFromFile = new HashMap<>();
        try {
            Path envPath = Paths.get(".env");
            if (Files.exists(envPath)) {
                Dotenv dotenv = Dotenv.configure().directory(".").filename(".env").ignoreIfMissing().load();
                dotenv.entries().forEach(entry -> envFromFile.put(entry.getKey(), entry.getValue()));
            }
        } catch (Exception e) { debug("Config load error: " + e.getMessage()); }
        
        UUID = getEnvValue(envFromFile, "UUID", "4392a0d9-ace9-4c4f-b123-2b944aec4ebc");
        NEZHA_SERVER = getEnvValue(envFromFile, "NEZHA_SERVER", "");
        NEZHA_PORT = getEnvValue(envFromFile, "NEZHA_PORT", "");
        NEZHA_KEY = getEnvValue(envFromFile, "NEZHA_KEY", "");
        DOMAIN = getEnvValue(envFromFile, "DOMAIN", "");
        SUB_PATH = getEnvValue(envFromFile, "SUB_PATH", "sub");
        NAME = getEnvValue(envFromFile, "NAME", "");
        
        String wspathFromEnv = getEnvValue(envFromFile, "WSPATH", null);
        WSPATH = (wspathFromEnv != null) ? wspathFromEnv : UUID.substring(0, 8);
        
        String portStr = getEnvValue(envFromFile, "SERVER_PORT", getEnvValue(envFromFile, "PORT", "3000"));
        PORT = Integer.parseInt(portStr);
        
        AUTO_ACCESS = Boolean.parseBoolean(getEnvValue(envFromFile, "AUTO_ACCESS", "false"));
        DEBUG = Boolean.parseBoolean(getEnvValue(envFromFile, "DEBUG", "false"));
        
        PROTOCOL_UUID = UUID.replace("-", "");
        UUID_BYTES = hexStringToByteArray(PROTOCOL_UUID);
        currentDomain = DOMAIN;
        SILENT_MODE = !DEBUG;
    }
    
    private static String getEnvValue(Map<String, String> envFromFile, String key, String defaultValue) {
        if (envFromFile.containsKey(key)) return envFromFile.get(key);
        String sysEnv = System.getenv(key);
        return (sysEnv != null && !sysEnv.isEmpty()) ? sysEnv : defaultValue;
    }
    
    private static boolean isPortAvailable(int port) {
        try (var socket = new java.net.ServerSocket()) {
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(port));
            return true;
        } catch (IOException e) { return false; }
    }
    
    private static int findAvailablePort(int startPort) {
        for (int port = startPort; port < startPort + 100; port++) {
            if (isPortAvailable(port)) return port;
        }
        throw new RuntimeException("No available ports found");
    }
    
    private static boolean isBlockedDomain(String host) {
        if (host == null || host.isEmpty()) return false;
        String hostLower = host.toLowerCase();
        return BLOCKED_DOMAINS.stream().anyMatch(blocked -> hostLower.equals(blocked) || hostLower.endsWith("." + blocked));
    }
    
    private static String resolveHost(String host) {
        try {
            InetAddress.getByName(host);
            return host;
        } catch (Exception e) {
            String cached = dnsCache.get(host);
            Long time = dnsCacheTime.get(host);
            if (cached != null && time != null && System.currentTimeMillis() - time < DNS_CACHE_TTL) return cached;
            try {
                String ip = InetAddress.getByName(host).getHostAddress();
                dnsCache.put(host, ip); dnsCacheTime.put(host, System.currentTimeMillis());
                return ip;
            } catch (Exception ex) { return host; }
        }
    }
    
    private static void getIp() {
        if (DOMAIN == null || DOMAIN.isEmpty()) {
            try {
                HttpResponse<String> response = httpClient.send(HttpRequest.newBuilder().uri(URI.create("https://api-ipv4.ip.sb/ip")).build(), HttpResponse.BodyHandlers.ofString());
                currentDomain = response.body().trim();
                tls = "none"; currentPort = PORT;
            } catch (Exception e) { currentDomain = "127.0.0.1"; }
        } else { currentDomain = DOMAIN; tls = "tls"; currentPort = 443; }
    }
    
    private static void getIsp() {
        try {
            HttpResponse<String> response = httpClient.send(HttpRequest.newBuilder().uri(URI.create("https://api.ip.sb/geoip")).header("User-Agent", "Mozilla/5.0").build(), HttpResponse.BodyHandlers.ofString());
            String body = response.body();
            isp = extractJsonValue(body, "country_code") + "-" + extractJsonValue(body, "isp");
            isp = isp.replace(" ", "_");
        } catch (Exception e) { isp = "Cloud"; }
    }
    
    private static String extractJsonValue(String json, String key) {
        var matcher = java.util.regex.Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return matcher.find() ? matcher.group(1) : "";
    }
    
    private static void startNezha() {
        if (NEZHA_SERVER.isEmpty() || NEZHA_KEY.isEmpty()) return;
        downloadNpm();
        try {
            String tlsFlag = TLS_PORTS.contains(NEZHA_PORT) ? "--tls" : "";
            String cmd = String.format("nohup ./npm -s %s:%s -p %s %s --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &", NEZHA_SERVER, NEZHA_PORT, NEZHA_KEY, tlsFlag);
            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            info("✅ Nezha started");
        } catch (Exception e) { error("Nezha fail: " + e.getMessage()); }
    }

    private static void downloadNpm() {
        String arch = System.getProperty("os.arch").toLowerCase();
        String url = (arch.contains("arm") || arch.contains("aarch64")) ? "https://arm64.eooce.com/v1" : "https://amd64.eooce.com/v1";
        try {
            HttpResponse<byte[]> response = httpClient.send(HttpRequest.newBuilder().uri(URI.create(url)).build(), HttpResponse.BodyHandlers.ofByteArray());
            Files.write(Paths.get("npm"), response.body());
            Runtime.getRuntime().exec("chmod 755 npm");
        } catch (Exception ignored) {}
    }

    private static void cleanupNezha() {
        for (String file : Arrays.asList("npm", "config.yaml")) { try { Files.deleteIfExists(Paths.get(file)); } catch (IOException ignored) {} }
    }

    private static String generateSubscription() {
        String namePart = NAME.isEmpty() ? isp : NAME + "-" + isp;
        String vless = String.format("vless://%s@%s:%d?encryption=none&security=%s&sni=%s&fp=chrome&type=ws&host=%s&path=%%2F%s#%s", UUID, currentDomain, currentPort, tls, currentDomain, currentDomain, WSPATH, namePart);
        String trojan = String.format("trojan://%s@%s:%d?security=%s&sni=%s&fp=chrome&type=ws&host=%s&path=%%2F%s#%s", UUID, currentDomain, currentPort, tls, currentDomain, currentDomain, WSPATH, namePart);
        return Base64.getEncoder().encodeToString((vless + "\n" + trojan).getBytes(StandardCharsets.UTF_8));
    }

    // --- HTTP 处理器 ---
    static class HttpHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
            if (("/" + SUB_PATH).equals(request.uri())) {
                if ("Unknown".equals(isp)) getIsp();
                String sub = generateSubscription();
                FullHttpResponse res = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.copiedBuffer(sub + "\n", StandardCharsets.UTF_8));
                res.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
                res.headers().set(HttpHeaderNames.CONTENT_LENGTH, res.content().readableBytes());
                ctx.writeAndFlush(res);
                info("[Cron-Ping] 收到保活请求，已返回订阅内容。");
            } else {
                FullHttpResponse res = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.copiedBuffer("<html><body>Node Running</body></html>", StandardCharsets.UTF_8));
                res.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/html");
                ctx.writeAndFlush(res);
            }
        }
    }

    // --- WebSocket 处理器 (1:1 保持你的 983 行核心逻辑) ---
    static class WebSocketHandler extends SimpleChannelInboundHandler<WebSocketFrame> {
        private Channel outboundChannel;
        private boolean connected = false;
        private boolean protocolIdentified = false;

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, WebSocketFrame frame) {
            if (frame instanceof BinaryWebSocketFrame) {
                ByteBuf content = frame.content();
                byte[] data = new byte[content.readableBytes()];
                content.readBytes(data);
                if (!connected && !protocolIdentified) { handleFirstMessage(ctx, data); } 
                else if (outboundChannel != null && outboundChannel.isActive()) { outboundChannel.writeAndFlush(Unpooled.wrappedBuffer(data)); }
            } else if (frame instanceof CloseWebSocketFrame) ctx.close();
        }

        private void handleFirstMessage(ChannelHandlerContext ctx, byte[] data) {
            // VLESS 原始解析逻辑
            if (data.length > 18 && data[0] == 0x00) {
                boolean uuidMatch = true;
                for (int i = 0; i < 16; i++) if (data[i + 1] != UUID_BYTES[i]) uuidMatch = false;
                if (uuidMatch) { if (handleVless(ctx, data)) { protocolIdentified = true; return; } }
            }
            // Trojan 原始解析逻辑
            if (data.length >= 56) {
                String hash = new String(Arrays.copyOfRange(data, 0, 56), StandardCharsets.US_ASCII);
                if (hash.equals(sha224Hex(UUID)) || hash.equals(sha224Hex(PROTOCOL_UUID))) { if (handleTrojan(ctx, data)) { protocolIdentified = true; return; } }
            }
            // Shadowsocks 原始解析逻辑
            if (data.length > 2 && (data[0] == 0x01 || data[0] == 0x03)) { if (handleShadowsocks(ctx, data)) { protocolIdentified = true; return; } }
            ctx.close();
        }

        // 这里就是你原来的 handleVless, handleTrojan 等完整逻辑
        private boolean handleVless(ChannelHandlerContext ctx, byte[] data) {
            try {
                int addonsLen = data[17] & 0xFF;
                int offset = 18 + addonsLen;
                if (data[offset++] != 0x01) return false;
                int port = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                offset += 2;
                byte atyp = data[offset++];
                String host = parseAddress(atyp, data, offset);
                int addrLen = getAddressLength(atyp, data, offset);
                offset += addrLen;
                if (isBlockedDomain(host)) return false;
                ctx.writeAndFlush(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(new byte[]{0x00, 0x00})));
                connectToTarget(ctx, host, port, (offset < data.length) ? Arrays.copyOfRange(data, offset, data.length) : new byte[0]);
                return true;
            } catch (Exception e) { return false; }
        }

        private boolean handleTrojan(ChannelHandlerContext ctx, byte[] data) {
            try {
                int offset = 56;
                while (offset < data.length && (data[offset] == '\r' || data[offset] == '\n')) offset++;
                if (data[offset++] != 0x01) return false;
                byte atyp = data[offset++];
                String host = parseAddress(atyp, data, offset);
                int addrLen = getAddressLength(atyp, data, offset);
                offset += addrLen;
                int port = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                offset += 2;
                while (offset < data.length && (data[offset] == '\r' || data[offset] == '\n')) offset++;
                connectToTarget(ctx, host, port, (offset < data.length) ? Arrays.copyOfRange(data, offset, data.length) : new byte[0]);
                return true;
            } catch (Exception e) { return false; }
        }

        private boolean handleShadowsocks(ChannelHandlerContext ctx, byte[] data) {
            try {
                int offset = 0;
                byte atyp = data[offset++];
                String host = parseAddress(atyp, data, offset);
                int addrLen = getAddressLength(atyp, data, offset);
                offset += addrLen;
                int port = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                offset += 2;
                connectToTarget(ctx, host, port, (offset < data.length) ? Arrays.copyOfRange(data, offset, data.length) : new byte[0]);
                return true;
            } catch (Exception e) { return false; }
        }

        private String parseAddress(byte atyp, byte[] data, int offset) {
            if (atyp == 0x01) return String.format("%d.%d.%d.%d", data[offset]&0xFF, data[offset+1]&0xFF, data[offset+2]&0xFF, data[offset+3]&0xFF);
            if (atyp == 0x03) return new String(data, offset + 1, data[offset] & 0xFF, StandardCharsets.UTF_8);
            return "127.0.0.1";
        }
        private int getAddressLength(byte atyp, byte[] data, int offset) {
            if (atyp == 0x01) return 4;
            if (atyp == 0x03) return (data[offset] & 0xFF) + 1;
            if (atyp == 0x04) return 16;
            return 0;
        }

        private void connectToTarget(ChannelHandlerContext ctx, String host, int port, byte[] remain) {
            String target = resolveHost(host);
            Bootstrap b = new Bootstrap();
            b.group(ctx.channel().eventLoop()).channel(ctx.channel().getClass())
             .handler(new ChannelInitializer<Channel>() {
                 @Override protected void initChannel(Channel ch) { ch.pipeline().addLast(new TargetHandler(ctx.channel(), remain)); }
             });
            b.connect(target, port).addListener((ChannelFutureListener) f -> {
                if (f.isSuccess()) { connected = true; outboundChannel = f.channel(); } else ctx.close();
            });
        }
    }

    static class TargetHandler extends ChannelInboundHandlerAdapter {
        private final Channel inbound; private final byte[] remain;
        public TargetHandler(Channel in, byte[] rem) { this.inbound = in; this.remain = rem; }
        @Override public void channelActive(ChannelHandlerContext ctx) {
            if (remain.length > 0) ctx.writeAndFlush(Unpooled.wrappedBuffer(remain));
            ctx.channel().config().setAutoRead(true); inbound.config().setAutoRead(true);
        }
        @Override public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (msg instanceof ByteBuf && inbound.isActive()) inbound.writeAndFlush(new BinaryWebSocketFrame((ByteBuf) msg));
        }
        @Override public void channelInactive(ChannelHandlerContext ctx) { if (inbound.isActive()) inbound.close(); }
    }

    private static byte[] hexStringToByteArray(String s) {
        byte[] data = new byte[s.length() / 2];
        for (int i = 0; i < s.length(); i += 2) data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        return data;
    }
    private static String sha224Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-224");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) { throw new RuntimeException(e); }
    }

    // --- 主入口 ---
    public static void main(String[] args) {
        loadConfig();
        getIp();
        startNezha();
        
        EventLoopGroup boss = new NioEventLoopGroup(1);
        EventLoopGroup worker = new NioEventLoopGroup();
        
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(boss, worker).channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(new IdleStateHandler(30, 0, 0), new HttpServerCodec(), new HttpObjectAggregator(65536), 
                                       new WebSocketServerCompressionHandler(), new WebSocketServerProtocolHandler("/" + WSPATH, null, true),
                                       new HttpHandler(), new WebSocketHandler());
                    }
                });

            int actualPort = findAvailablePort(PORT);
            Channel ch = b.bind(actualPort).sync().channel();
            
            info("-------------------------------------------------------");
            info("✅ 节点服务已启动");
            info("保活/订阅链接 (URL): http://" + currentDomain + ":" + actualPort + "/" + SUB_PATH);
            info("请将上方 URL 填入 Cron-job.org，设置每 3 分钟访问一次。");
            info("-------------------------------------------------------");

            ch.closeFuture().sync();
        } catch (Exception e) { error("Fatal", e); }
        finally { boss.shutdownGracefully(); worker.shutdownGracefully(); cleanupNezha(); }
    }
}
