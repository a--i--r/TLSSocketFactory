package my.tls;

import java.security.Principal;
import java.security.cert.Certificate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;

import org.bouncycastle.crypto.tls.CipherSuite;

public class TLSSession implements SSLSession {

	private Certificate[] peerCertArray;
	protected TLSClient tlsClient;
	private long created;

	public TLSSession(TLSClient tlsClient) {
		super();
		created = System.currentTimeMillis();
		this.tlsClient = tlsClient;
	}

	public TLSClient getTlsClient() {
        return tlsClient;
    }

    public void setTlsClient(TLSClient tlsClient) {
        this.tlsClient = tlsClient;
    }

    /**
	 * peerCertArray を取得します
	 * @return peerCertArray
	 */
	public Certificate[] getPeerCertArray() {
		return peerCertArray;
	}

	/**
	 * peerCertArray を設定します
	 * @param peerCertArray
	 */
	public void setPeerCertArray(Certificate[] peerCertArray) {
		this.peerCertArray = peerCertArray;
	}

	@Override
	public int getApplicationBufferSize() {
		return 0;
	}

	@Override
	public String getCipherSuite() {

		switch (this.tlsClient.getSelectedCipherSuite()) {

		case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		    return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";

		case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		    return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";

		case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		    return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";

		case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
		    return "TLS_RSA_WITH_AES_128_GCM_SHA256";

		case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
		    return "TLS_RSA_WITH_AES_128_CBC_SHA256";

		case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
		    return "TLS_RSA_WITH_AES_128_CBC_SHA";

		default:
		    throw new UnsupportedOperationException();
		}
	}

	@Override
	public long getCreationTime() {
		return created;
	}

	@Override
	public byte[] getId() {
		return this.tlsClient.getSession().getSessionID();
	}

	@Override
	public long getLastAccessedTime() {
		return System.currentTimeMillis();
	}

	@Override
	public Certificate[] getLocalCertificates() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Principal getLocalPrincipal() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getPacketBufferSize() {
		return 0;
	}

	@Override
	public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
		return null;
	}

	@Override
	public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
		return peerCertArray;
	}

	@Override
	public String getPeerHost() {
		return this.tlsClient.getHost();
	}

	@Override
	public int getPeerPort() {
		return this.tlsClient.getPort();
	}

	@Override
	public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
		return null;
	}

	@Override
	public String getProtocol() {
		switch (this.tlsClient.getProtocol().getFullVersion()) {
		case 0x0301:
		    return "TLSv1";
		case 0x0302:
		    return "TLSv1.1";
		case 0x0303:
		    return "TLSv1.2";
		default:
		    throw new IllegalStateException();
		}
	}

	@Override
	public SSLSessionContext getSessionContext() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object getValue(String paramString) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String[] getValueNames() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void invalidate() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isValid() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void putValue(String paramString, Object paramObject) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeValue(String paramString) {
		throw new UnsupportedOperationException();
	}

}
