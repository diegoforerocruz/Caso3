package ServidorSinSeguridad;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Random;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

public class D extends Thread {
  public static final String OK = "OK";
  
  public static final String ALGORITMOS = "ALGORITMOS";
  
  public static final String CERTSRV = "CERTSRV";
  
  public static final String CERCLNT = "CERCLNT";
  
  public static final String SEPARADOR = ":";
  
  public static final String HOLA = "HOLA";
  
  public static final String INICIO = "INICIO";
  
  public static final String ERROR = "ERROR";
  
  public static final String REC = "recibio-";
  
  public static final String ENVIO = "envio-";
  
  private Socket sc = null;
  
  private String dlg;
  
  private byte[] mybyte;
  
  private static X509Certificate certSer;
  
  private static KeyPair keyPairServidor;
  
  public static void init(X509Certificate pCertSer, KeyPair pKeyPairServidor) {
    certSer = pCertSer;
    keyPairServidor = pKeyPairServidor;
  }
  
  public D(Socket csP, int idP) {
    this.sc = csP;
    this.dlg = new String("delegado " + idP + ": ");
    try {
      this.mybyte = new byte[520];
      this.mybyte = certSer.getEncoded();
    } catch (Exception e) {
      System.out.println("Error creando el thread" + this.dlg);
      e.printStackTrace();
    } 
  }
  
  private boolean validoAlgHMAC(String nombre) {
    return !(!nombre.equals("HMACMD5") && 
      !nombre.equals("HMACSHA1") && 
      !nombre.equals("HMACSHA256") && 
      !nombre.equals("HMACSHA384") && 
      !nombre.equals("HMACSHA512"));
  }
  
  public void run() {
    System.out.println(String.valueOf(this.dlg) + "Empezando atencion.");
    try {
      PrintWriter ac = new PrintWriter(this.sc.getOutputStream(), true);
      BufferedReader dc = new BufferedReader(new InputStreamReader(this.sc.getInputStream()));
      String linea = dc.readLine();
      if (!linea.equals("HOLA")) {
        ac.println("ERROR");
        this.sc.close();
        throw new Exception(String.valueOf(this.dlg) + "ERROR" + "recibio-" + linea + "-terminando.");
      } 
      ac.println("OK");
      String feedback = String.valueOf(this.dlg) + "recibio-" + linea + "-continuando.";
      System.out.println(feedback);
      linea = dc.readLine();
      if (!linea.contains(":") || !linea.split(":")[0].equals("ALGORITMOS")) {
        ac.println("ERROR");
        this.sc.close();
        throw new Exception(String.valueOf(this.dlg) + "ERROR" + "recibio-" + linea + "-terminando.");
      } 
      String[] algoritmos = linea.split(":");
      if (!algoritmos[1].equals("DES") && !algoritmos[1].equals("AES") && 
        !algoritmos[1].equals("Blowfish") && !algoritmos[1].equals("RC4")) {
        ac.println("ERROR");
        this.sc.close();
        throw new Exception(String.valueOf(this.dlg) + "ERROR" + "Alg.Simetrico" + "recibio-" + algoritmos + "-terminando.");
      } 
      if (!algoritmos[2].equals("RSA")) {
        ac.println("ERROR");
        this.sc.close();
        throw new Exception(String.valueOf(this.dlg) + "ERROR" + "Alg.Asimetrico." + "recibio-" + algoritmos + "-terminando.");
      } 
      if (!validoAlgHMAC(algoritmos[3])) {
        ac.println("ERROR");
        this.sc.close();
        throw new Exception(String.valueOf(this.dlg) + "ERROR" + "AlgHash." + "recibio-" + algoritmos + "-terminando.");
      } 
      feedback = String.valueOf(this.dlg) + "recibio-" + linea + "-continuando.";
      System.out.println(feedback);
      ac.println("OK");
      feedback = String.valueOf(this.dlg) + "envio-" + "OK" + "-continuando.";
      System.out.println(feedback);
      String strCertificadoCliente = dc.readLine();
      byte[] certificadoClienteBytes = new byte[520];
      certificadoClienteBytes = toByteArray(strCertificadoCliente);
      CertificateFactory creador = CertificateFactory.getInstance("X.509");
      InputStream in = new ByteArrayInputStream(certificadoClienteBytes);
      X509Certificate certificadoCliente = (X509Certificate)creador.generateCertificate(in);
      feedback = String.valueOf(this.dlg) + "recibio-" + "certificado del cliente. continuando.";
      System.out.println(feedback);
      ac.println("OK");
      feedback = String.valueOf(this.dlg) + "envio-" + "OK" + "-continuando.";
      System.out.println(feedback);
      String strSerCert = toHexString(this.mybyte);
      ac.println(strSerCert);
      feedback = String.valueOf(this.dlg) + "envio-" + " certificado del servidor. continuando.";
      System.out.println(feedback);
      linea = dc.readLine();
      if (!linea.equals("OK")) {
        this.sc.close();
        throw new Exception(String.valueOf(this.dlg) + "ERROR" + "recibio-" + linea + "-terminando.");
      } 
      feedback = String.valueOf(this.dlg) + "recibio-" + linea + "-continuando.";
      System.out.println(feedback);
      SecretKey simetrica = S.kgg(algoritmos[1]);
      byte[] ciphertext1 = S.ae(simetrica.getEncoded(), 
          certificadoCliente.getPublicKey(), algoritmos[2]);
      ac.println(toHexString(ciphertext1));
      feedback = String.valueOf(this.dlg) + "envio-" + "llave K_SC al cliente. continuado.";
      System.out.println(feedback);
      Random rand = new Random();
      int intReto = rand.nextInt(9999);
      String strReto = (new StringBuilder(String.valueOf(intReto))).toString();
      for (; strReto.length() % 4 != 0; strReto = String.valueOf(strReto) + Character.MIN_VALUE);
      String reto = strReto;
      byte[] bytereto = toByteArray(reto);
      //byte[] cipherreto = S.se(bytereto, simetrica, algoritmos[1]);
      ac.println(toHexString(bytereto));
      feedback = String.valueOf(this.dlg) + "envio-" + reto + "-reto al cliente. continuando ";
      System.out.println(feedback);
      linea = dc.readLine();
      byte[] retodelcliente = toByteArray(linea);
      String strdelcliente = toHexString(retodelcliente);
      if (strdelcliente.equals(reto)) {
        System.out.println(String.valueOf(this.dlg) + "recibio-" + reto + "-reto correcto. continuado.");
        ac.println("OK");
      } else {
        ac.println("ERROR");
        this.sc.close();
        throw new Exception(String.valueOf(this.dlg) + "recibio-" + reto + "-ERROR en reto. terminando");
      } 
      linea = dc.readLine();
      byte[] retoByte = toByteArray(linea);
      //byte[] ciphertext2 = S.sd(retoByte, simetrica, algoritmos[1]);
      String nombre = toHexString(retoByte);
      feedback = String.valueOf(this.dlg) + "recibio-" + nombre + "-continuando";
      System.out.println(feedback);
      Calendar rightNow = Calendar.getInstance();
      int hora = rightNow.get(11);
      int minuto = rightNow.get(12);
      String strvalor = (new StringBuilder(String.valueOf(hora * 100 + minuto))).toString();
      for (; strvalor.length() % 4 != 0; strvalor = String.valueOf(strvalor) + " ");
      byte[] valorByte = toByteArray(strvalor);
      
      ac.println(toHexString(valorByte));
      feedback = String.valueOf(this.dlg) + "envio-" + strvalor + "-cifrado con K_SC. continuado.";
      System.out.println(feedback);
      linea = dc.readLine();
      if (linea.equals("OK")) {
        feedback = String.valueOf(this.dlg) + "recibio-" + linea + "-Terminando exitosamente.";
        System.out.println(feedback);
      } else {
        feedback = String.valueOf(this.dlg) + "recibio-" + linea + "-Terminando con error";
        System.out.println(feedback);
      } 
      this.sc.close();
    } catch (Exception e) {
      e.printStackTrace();
    } 
  }
  
  public static String toHexString(byte[] array) {
    return DatatypeConverter.printBase64Binary(array);
  }
  
  public static byte[] toByteArray(String s) {
    return DatatypeConverter.parseBase64Binary(s);
  }
}
