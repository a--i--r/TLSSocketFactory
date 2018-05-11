package my.tls;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.security.Security;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * TLS socket factory powered by bouncyCastle
 * @author koji.hayakawa
 *
 */
public class TLSSocketFactory extends SSLSocketFactory {

    // default socket timeout (0:infinite)
    public static final int SOCKET_TIMEOUT = 0;

	// add bouncycastle provider
	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	// random number generator
	private SecureRandom           secureRandom;
	private boolean               selfSignPass = false;
	private int                    soTimeout = SOCKET_TIMEOUT;

    public TLSSocketFactory() {
		secureRandom = new SecureRandom();
	}

	public TLSSocketFactory(boolean selfSignPass) {
	    this();
	    this.selfSignPass = selfSignPass;
	}
	public TLSSocketFactory(boolean selfSignPass, int soTimeout) {
	    this(selfSignPass);
	    this.setSoTimeout(soTimeout);
	}

	public boolean isSelfSignPass() {
        return selfSignPass;
    }
    public void setSelfSignPass(boolean selfSignPass) {
        this.selfSignPass = selfSignPass;
    }
    public int getSoTimeout() {
        return soTimeout;
    }
    public void setSoTimeout(int soTimeout) {
        this.soTimeout = soTimeout;
    }

    @Override
	public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {

		if (socket == null) {
			socket = new Socket();
		}
		socket.setSoTimeout(this.soTimeout);

		if (!socket.isConnected()) {
			socket.connect(new InetSocketAddress(host, port));
		}
		TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(socket.getInputStream(),
				socket.getOutputStream(), this.secureRandom);
		return _createSSLSocket(host, port, tlsClientProtocol);
	}

	private SSLSocket _createSSLSocket(String host, int port, TlsClientProtocol tlsClientProtocol) {

		return new TLSSocket(host, port, tlsClientProtocol, selfSignPass);
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return TLSSocket.CIPHER_SUITES;
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return TLSSocket.CIPHER_SUITES;
	}

	@Override
	public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
		return createSocket(null, host, port, false);
	}

	@Override
	public Socket createSocket(InetAddress host, int port) throws IOException {
		return createSocket(null, host.getHostName(), port, false);
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
			throws IOException, UnknownHostException {
		return null;
	}

	@Override
	public Socket createSocket(InetAddress arg0, int arg1, InetAddress arg2, int arg3) throws IOException {
		return null;
	}

}
