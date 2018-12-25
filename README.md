# TLSSocketFactory
TLSSocketFacory is TLS1.2 (HTTPS connection) capable with Java6 powered by BouncyCastle

## License
MIT X11 License

## How to use

* normal  
`HttpsURLConnection.setDefaultSSLSocketFactory(new TLSSocketFactory());`

* self-signed certificate connectable  
`HttpsURLConnection.setDefaultSSLSocketFactory(new TLSSocketFactory(true));`

* configure socket timeout (millisec: default=0)  
`HttpsURLConnection.setDefaultSSLSocketFactory(new TLSSocketFactory(true, 60000));`

## BouncyCastle maven repository
		<!-- https://mvnrepository.com/artifact/org.bouncycastle/bcprov-debug-jdk15on -->
		<dependency>
			<groupId>org.bouncycastle</groupId>
			<artifactId>bcprov-debug-jdk15on</artifactId>
			<version>1.55</version>
		</dependency>
		<!-- https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15on -->
		<dependency>
			<groupId>org.bouncycastle</groupId>
			<artifactId>bcpkix-jdk15on</artifactId>
			<version>1.55</version>
		</dependency>
