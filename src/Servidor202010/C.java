package Servidor202010;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import ServidorSinSeguridad.D;


public class C {
	private static ServerSocket ss;	
	private static final String MAESTRO = "MAESTRO: ";
	private static X509Certificate certSer; /* acceso default */
	private static KeyPair keyPairServidor; /* acceso default */

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception{
		System.out.println(MAESTRO + "Establezca puerto de conexion:");
		InputStreamReader isr = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(isr);
		int ip = Integer.parseInt(br.readLine());
		System.out.println(MAESTRO + "Empezando servidor maestro en puerto " + ip);
		// Adiciona la libreria como un proveedor de seguridad.
		Security.addProvider(new BouncyCastleProvider());		

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
		File file2 = new File("./tiempoDeEjecucion.txt");
		if (!file2.exists()) {
			file2.createNewFile();
		}
		FileWriter fw2 = new FileWriter(file2);
		fw2.close();
		D.init(certSer, keyPairServidor,file, file2);

		// Crea el socket que escucha en el puerto seleccionado.
		ss = new ServerSocket(ip);
		System.out.println("MAESTRO: Socket creado.");

		System.out.println("Ingresar el número de Threads que va a tener el Pool:");
		int peticiones = Integer.parseInt(br.readLine());

		ExecutorService pool = Executors.newFixedThreadPool(peticiones);

		for (int i=0;true;i++) {
			try { 
				Socket sc = ss.accept();
				System.out.println(MAESTRO + "Cliente " + i + " aceptado.");
				pool.execute(new Servidor202010.D(sc,i));

			} catch (IOException e) {
				System.out.println(MAESTRO + "Error creando el socket cliente.");
				e.printStackTrace();
			}
		}
	}
}
