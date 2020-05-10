package ServidorSinSeguridad;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
    D.init(certSer, keyPairServidor);
    ss = new ServerSocket(ip);
    System.out.println("MAESTRO: Socket creado.");
    for (int i = 0;; i++) {
      try {
        Socket sc = ss.accept();
        System.out.println("MAESTRO: Cliente " + i + " aceptado.");
        D d = new D(sc, i);
        d.start();
      } catch (IOException e) {
        System.out.println("MAESTRO: Error creando el socket cliente.");
        e.printStackTrace();
      } 
    } 
  }
}
