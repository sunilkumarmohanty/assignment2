import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.security.Principal;
import java.io.*;
import javax.net.ssl.HttpsURLConnection;
import java.security.cert.*;
import javax.net.ssl.*;
import javax.net.*;
import java.text.SimpleDateFormat;
public class certificate2 {

    /**
     * @param args
     */

    public static void main(String[] args) {
        try{
            URL url = new URL("https://expired.badssl.com/");
            //URL url = new URL("https://google.com/");

            SSLContext sslCtx = SSLContext.getInstance("TLS");
            sslCtx.init(null, new TrustManager[]{ new X509TrustManager() {

                private X509Certificate[] accepted;

                @Override
                public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
                    accepted = xcs;
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return accepted;
                }
            }}, null);

            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

            connection.setHostnameVerifier(new HostnameVerifier() {

                @Override
                public boolean verify(String string, SSLSession ssls) {
                    return true;
                }
            });

            connection.setSSLSocketFactory(sslCtx.getSocketFactory());

            if (connection.getResponseCode() == 200) {
                Certificate[] certificates = connection.getServerCertificates();
                System.out.println("certificates.length "+certificates.length);
                for (int i = 0; i < certificates.length; i++) {
                    Certificate cert = certificates[i];
                    X509Certificate x509cert = (X509Certificate) cert;
                    System.out.println("Certificate " + i + " :");
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


                    try{
                        //cert.verify(x509cert.getPublicKey());
                        SimpleDateFormat df = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
                        System.out.println(df.format(x509cert.getNotAfter()));
                        x509cert.checkValidity();
                    }catch (CertificateExpiredException cee) {
                        System.out.println("Certificate is expired");
                    } catch (Exception ex) {
                        System.out.println(ex.toString());
                    }
                }
            }}catch(Exception ex){
            ex.printStackTrace();
        }

    }

    public certificate2() {
        super();
    }
    private void print_content(HttpsURLConnection con) {
        if (con != null) {
            try {
                System.out.println("HTTP response:");
                BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
                String input;
                while ((input = br.readLine()) != null) {
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
