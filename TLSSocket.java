package my.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.crypto.tls.TlsClientProtocol;

public class TLSSocket extends SSLSocket {

    public static final String[] SUPPORT_PROTOCOLS = { "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2" };
	public static final String[] ENABLED_PROTOCOLS = { "TLSv1", "TLSv1.1", "TLSv1.2" };
	public static final String[] CIPHER_SUITES = {
	        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	        "TLS_RSA_WITH_AES_128_GCM_SHA256",
	        "TLS_RSA_WITH_AES_128_CBC_SHA256",
	        "TLS_RSA_WITH_AES_128_CBC_SHA"
	};

	protected String			host = "";
	protected int               port;
	protected boolean           selfSignPass = false;
	protected TLSSession		session;
	protected TlsClientProtocol	tlsClientProtocol;
	protected List<HandshakeCompletedListener> listeners = new CopyOnWriteArrayList<HandshakeCompletedListener>();

	public TLSSocket(String host, int port, TlsClientProtocol in, boolean selfSignPass) {
		super();
		this.host = host;
		this.port = port;
		tlsClientProtocol = in;
		this.selfSignPass = selfSignPass;
	}

	public boolean isSelfSignPass() {
        return selfSignPass;
    }

    @Override
	public InputStream getInputStream() {
	    return tlsClientProtocol.getInputStream();
	}

	@Override
	public OutputStream getOutputStream() {
	    return tlsClientProtocol.getOutputStream();
	}

	@Override
	public void addHandshakeCompletedListener(HandshakeCompletedListener arg0) {
		listeners.add(arg0);
	}

	@Override
	public boolean getEnableSessionCreation() {
		return false;
	}

	@Override
	public String[] getEnabledCipherSuites() {
		return CIPHER_SUITES;
	}

	@Override
	public String[] getEnabledProtocols() {
		return ENABLED_PROTOCOLS;
	}

	@Override
	public boolean getNeedClientAuth() {
		return false;
	}

	@Override
	public SSLSession getSession() {
		return this.session;
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return CIPHER_SUITES;
	}

	@Override
	public String[] getSupportedProtocols() {
		return SUPPORT_PROTOCOLS;
	}

	@Override
	public boolean getUseClientMode() {
		return false;
	}

	@Override
	public boolean getWantClientAuth() {
		return false;
	}

	@Override
	public void removeHandshakeCompletedListener(HandshakeCompletedListener arg0) {
	    listeners.remove(arg0);
	}

	@Override
	public void setEnableSessionCreation(boolean arg0) {
	}

	@Override
	public void setEnabledCipherSuites(String[] arg0) {
	}

	@Override
	public void setEnabledProtocols(String[] arg0) {
	}

	@Override
	public void setNeedClientAuth(boolean arg0) {
	}

	@Override
	public void setUseClientMode(boolean arg0) {
	}

	@Override
	public void setWantClientAuth(boolean arg0) {
	}

	@Override
	public void startHandshake() throws IOException {

		TLSClient client = new TLSClient(host, port, this);
        this.session = new TLSSession(client);
		tlsClientProtocol.connect(client);

		for (HandshakeCompletedListener hcl: listeners) {
		    hcl.handshakeCompleted(new HandshakeCompletedEvent(this, this.session));
		}
	}

	public synchronized void close() throws IOException {
	    tlsClientProtocol.close();
	}

}
