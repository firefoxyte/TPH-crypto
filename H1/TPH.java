import java.math.BigInteger;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;


public class TPH {

	
	public static String toHex(byte[] donnes) {
        StringBuffer sb = new StringBuffer();        
        for(byte k: donnes) {
            sb.append(String.format("%02X", k));
        }        
        return sb.toString();
    }
	

	
   
    private static SecretKeySpec clefSecrete;

    private static byte[] buffer = new byte[1024];
    private static int nbOctetsLus; 
    private static FileInputStream fis;
    private static FileOutputStream fos;
    private static CipherInputStream cis;
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException
	    {
	        
            // Pour choisir des suites doctets aleatoires
            if(args.length != 2){
                System.out.println("usage: nom_fichier_a_crypter nom_fichier_crypter");
                return;
            }
	        SecureRandom alea = new SecureRandom();
	        
	     // Choix dune suite de 16 octets formant la clef secrete
	        byte[] k = new byte[16];
	        
	        alea.nextBytes(k); // remplit la clef doctets aleatoires
	        

	        byte[] iv = new byte[16];
	        alea.nextBytes(iv);
 
	        BigInteger e; //exposant public 1023 bits
	        e = new BigInteger("44bb1ff6c2b674798e09075609b7883497ae2e2d7b06861ef9850e26d1456280523319021062c8743544877923fe65f85111792a98e4b887de8ffd13aef18ff7f6f736c821cfdad98af051e7caaa575d30b54ed9a6ee901bb0ffc17e25d444f8bfc5922325ee2ef94bd4ee15bede2ea12eb623ad507d6b246a1f0c3cc419f155", 16);
	        BigInteger n; // module public 1024 bits
	        n = new BigInteger("94f28651e58a75781cfe69900174b86f855f092f09e3da2ad86b4ed964a84917e5ec60f4ee6e3adaa13962884e5cf8dae2e0d29c6168042ec9024ea11176a4ef031ac0f414918b7d13513ca1110ed80bd2532f8a7aab0314bf54fcaf621eda74263faf2a5921ffc515097a3c556bf86f2048a3c159fccfee6d916d38f7f23f21", 16);
	           
	        // Appel a une fabrique de clefs
	        KeyFactory usine = KeyFactory.getInstance("RSA");
	       
	        // Construction en 2 temps de la clef publique par la fabrique
	        RSAPublicKeySpec specClefPublique = new RSAPublicKeySpec(n,e);
	        RSAPublicKey clefPublique = (RSAPublicKey) usine.generatePublic(specClefPublique);
	      
	        

	     
	       

	                //------------------------------------------------------------------
	                //  Etape 1.   R�cup�rer un objet qui chiffre et d�chiffre en RSA
	                //             avec bourrage (mais sans mode operatoire : ECB)
	                //------------------------------------------------------------------
            
	                Cipher chiffreur1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	                
	                 //------------------------------------------------------------------
	                //  Etape 2.   Chiffrer la clé k puis ecrire le resultat suivi du vecteur
	                //------------------------------------------------------------------
	                
	                chiffreur1.init(Cipher.ENCRYPT_MODE, clefPublique);
	                byte[] messageChiffre = chiffreur1.doFinal(k);
	               
	                
	             
	               
	                FileOutputStream fichier = new FileOutputStream(args[1]);
                    fichier.write(messageChiffre);
                    fichier.write(iv);
	                fichier.close();

                    
	                
	                
	                
	                //H1 Q7
	                try {
                        fis = new FileInputStream(args[0]); 
                        fos = new FileOutputStream(args[1],true);
                    }
                    catch (Exception e1) { System.out.println("Fichier inexistant.");return;}	
                  
                    //------------------------------------------------------------------
                    //  Etape 3.   Recuperer un objet qui chiffre ou dechiffre en AES
                    //             dans le mode CBC (non-deterministe) avec bourrage standard.
                    //------------------------------------------------------------------
                    try {
                        chiffreur1 = Cipher.getInstance("AES/CBC/PKCS5Padding"); 
                    }
                    catch (Exception e1) { System.out.println("AES n'est pas disponible.");return;}	
                    //------------------------------------------------------------------
                    //  Etape 4.   Fabriquer la cle AES de 128 bits correspondante et
                    //             preparer le vecteur d'initialisation.
                    //------------------------------------------------------------------
                    clefSecrete = new SecretKeySpec(k, "AES");
                  
                    IvParameterSpec ivspec = new IvParameterSpec(iv);
                    //------------------------------------------------------------------
                    //  Etape 5.   Chiffrer le fichier et sauvegarder le resultat
                    //------------------------------------------------------------------
                    try {
                        chiffreur1.init(Cipher.ENCRYPT_MODE, clefSecrete, ivspec);
                        cis = new CipherInputStream(fis, chiffreur1);
                        
                        nbOctetsLus = cis.read(buffer);   
                        while (  nbOctetsLus != -1 ) {
                            fos.write(buffer, 0, nbOctetsLus);
                            nbOctetsLus = cis.read(buffer); 
                        }
                        fos.close();
                        cis.close();
                        fis.close();
                    } catch (Exception e1) { System.out.println("Chiffrement impossible:" + e1.getMessage());}	
                    
                    
          
	    }	     
}