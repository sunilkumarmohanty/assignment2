import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.security.Principal;
import java.io.*;
import javax.net.ssl.HttpsURLConnection;

public class TestSecuredConnection {

    /**
     * @param args
     */
    public static void main(String[] args) {
        TestSecuredConnection tester = new TestSecuredConnection();
        try {
            tester.testConnectionTo("https://google.com/");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public TestSecuredConnection() {
        super();
    }

    public void testConnectionTo(String aURL) throws Exception {
        URL destinationURL = new URL(aURL);
        HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
        conn.connect();
        Certificate[] certs = conn.getServerCertificates();
        System.out.println("hi2");
        int i=0;
        for (Certificate cert : certs) {

            if(cert instanceof X509Certificate) {
            try
            {
                //System.out.println("Cert Type : " + cert.toString());
                X509Certificate x509cert = (X509Certificate) cert;
                System.out.println("Certificate "+i+" :");
                //Issuer

                Principal iss_principal = x509cert.getIssuerX500Principal();
                String iss_principal_val = iss_principal.getName();
                //System.out.println(iss_principal_val);
                String[] iss_principal_vals = iss_principal_val.split(",");

                System.out.println("Issuer : ");
                System.out.println(" - Organization name : " + iss_principal_vals[1].split("=")[1]);
                System.out.println(" - Common name : " + iss_principal_vals[0].split("=")[1]);

                //Subject
                Principal sub_principal = x509cert.getSubjectX500Principal();
                String sub_principal_val = sub_principal.getName();
                //System.out.println(sub_principal_val);
                String[] sub_principal_vals = sub_principal_val.split(",");

                System.out.println("Subject : ");
                System.out.println(" - Organization name : " + sub_principal_vals[1].split("=")[1]);
                System.out.println(" - Common name : " + sub_principal_vals[0].split("=")[1]);
                i++;

                        //cert.verify(x509cert.getPublicKey());
                         ( (X509Certificate) cert).checkValidity();
                        // System.out.println("Certificate is active for current date");
                  }
                    catch(CertificateExpiredException cee) {
                    System.out.println("Certificate is expired");
                }
                catch(Exception ex)
                {
                    System.out.println("Error");
                }
            }

        }
        print_content(conn);
    }

    private void print_content(HttpsURLConnection con)
    {
   	  if(con!=null){
        try {
           	   System.out.println("HTTP response:");
           	   BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
           	   String input;
           	   while ((input = br.readLine()) != null){
           	      System.out.println(input);
                  System.out.println("[HTTP response omitted]");
                  break;
           	   }
           	   br.close();

           	} catch (IOException e) {
           	   e.printStackTrace();
           	}
          }
      }
}