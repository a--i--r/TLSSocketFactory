package my.tls;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ExtensionType;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.crypto.tls.TlsSession;
import org.bouncycastle.crypto.tls.TlsUtils;

public class TLSClient extends DefaultTlsClient {

	protected String host = "";
	protected int port;
	protected TLSSocket tlsSocket;
	protected TLSAuthentication tlsAuthentication;

	/**
	 * コンストラクタ
	 * @param host
	 * @param port
	 */
	public TLSClient(String host, int port, TLSSocket sock) {
	    super();
	    this.host = host;
	    this.port = port;
	    this.tlsSocket = sock;
	    this.tlsAuthentication = new TLSAuthentication(this);
	}

	public TLSSocket getTlsSocket() {
        return tlsSocket;
    }

    /**
	 * host を取得します
	 * @return host
	 */
	public String getHost() {
		return host;
	}
	/**
	 * host を設定します
	 * @param host
	 */
	public void setHost(String host) {
		this.host = host;
	}
	public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    /**
	 * session を取得します
	 * @return session
	 */
	public TlsSession getSession() {
	    return context.getResumableSession();
	}

	public boolean isTLSv12() {
	    return TlsUtils.isTLSv12(context);
	}

	public int getSelectedCipherSuite() {
	    return selectedCipherSuite;
	}

	public ProtocolVersion getProtocol() {
	    return context.getServerVersion();
	}

	@Override
	public Hashtable<Integer, byte[]> getClientExtensions() throws IOException {

		Hashtable<Integer, byte[]> clientExtensions = super.getClientExtensions();
		if (clientExtensions == null) {
			clientExtensions = new Hashtable<Integer, byte[]>();
		}
		// add hostname
		byte[] hostname = host.getBytes("UTF-8");

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		dos.writeShort(hostname.length+3); // entry size
		dos.writeByte(0); // name type = hostname
		dos.writeShort(hostname.length);
		dos.write(hostname);
		dos.close();

		clientExtensions.put(ExtensionType.server_name, baos.toByteArray());
		return clientExtensions;
	}

	@Override
	protected boolean allowUnexpectedServerExtension(Integer extensionType, byte[] extensionData) throws IOException {

		switch (extensionType.intValue()) {
		case ExtensionType.ec_point_formats:
			/*
			 * Exception added based on field reports that some servers send Supported
			 * Point Format Extension even when not negotiating an ECC cipher suite.
			 * If present, we still require that it is a valid ECPointFormatList.
			 */
			TlsECCUtils.readSupportedPointFormatsExtension(extensionData);
			return true;
		default:
			return super.allowUnexpectedServerExtension(extensionType, extensionData);
		}
	}

	@Override
	public TlsAuthentication getAuthentication() throws IOException {

		return this.tlsAuthentication;
	}

}
