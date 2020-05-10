package ServidorSinSeguridad;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import Servidor202010.D;
import Servidor202010.S;

public class C {
	private static ServerSocket ss;

	private static final String MAESTRO = "MAESTRO: ";

	private static X509Certificate certSer;

	private static KeyPair keyPairServidor;

	public static void main(String[] args) throws Exception {
		System.out.println("MAESTRO: Establezca puerto de conexion:");
		InputStreamReader isr = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(isr);
		int ip = Integer.parseInt(br.readLine());
		System.out.println("MAESTRO: Empezando servidor maestro en puerto " + ip);
		Security.addProvider((Provider)new BouncyCastleProvider());
		keyPairServidor = S.grsa();
		certSer = S.gc(keyPairServidor);

		// Crea el archivo de log
		File file = null;
		keyPairServidor = S.grsa();
		certSer = S.gc(keyPairServidor); 
		String ruta = "./resultados.txt";

		file = new File(ruta);
		if (!file.exists()) {
			file.createNewFile();
		}
		FileWriter fw = new FileWriter(file);
		fw.close();

		D.init(certSer, keyPairServidor, file);
		ss = new ServerSocket(ip);
		System.out.println("MAESTRO: Socket creado.");


		int numeroThreads = 0;

		ExecutorService es = Executors.newFixedThreadPool(1);


		System.out.println("Ingresar el número de peticiones que se van a realizar");
		int peticiones = Integer.parseInt(br.readLine());

		while(peticiones > 0) {
			try { 
				Socket sc = ss.accept();
				System.out.println(MAESTRO + "Cliente " + numeroThreads + " aceptado.");

				es.execute(new D(sc,numeroThreads));

				peticiones--;
				numeroThreads++;
			} catch (IOException e) {
				System.out.println("MAESTRO: Error creando el socket cliente.");
				e.printStackTrace();
			} 
		} 
	}
}
