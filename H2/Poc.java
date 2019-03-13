package src;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.lang.Byte;
public class Poc{
	
	public static BigInteger e = new BigInteger("44bb1ff6c2b674798e09075609b7883497ae2e2d7b06861ef9850e26d1456280523319021062c8743544877923fe65f85111792a98e4b887de8ffd13aef18ff7f6f736c821cfdad98af051e7caaa575d30b54ed9a6ee901bb0ffc17e25d444f8bfc5922325ee2ef94bd4ee15bede2ea12eb623ad507d6b246a1f0c3cc419f155",16);
	public static BigInteger n = new BigInteger("94f28651e58a75781cfe69900174b86f855f092f09e3da2ad86b4ed964a84917e5ec60f4ee6e3adaa13962884e5cf8dae2e0d29c6168042ec9024ea11176a4ef031ac0f414918b7d13513ca1110ed80bd2532f8a7aab0314bf54fcaf621eda74263faf2a5921ffc515097a3c556bf86f2048a3c159fccfee6d916d38f7f23f21",16); 
	public Runtime runtime = Runtime.getRuntime();
	public static String K;
	
	
	public Poc(int sizekey) {
		
		
		Random rn = new Random();
		K="";
		for(int i =0; i< sizekey; i++) {
			int nbrand = rn.nextInt(255);
			
			String tmp = new String(Integer.toHexString(nbrand));
			K+= tmp;
			
			
			
	
			
		}
	
	}

	public byte[] MGF(byte g[],int size) {
		
		byte tab[];
		int secu_taille;
		if(size%20 != 0) {
			
			secu_taille = (size/20) +1;
			tab= new byte[size+20];
		}
		else {
			secu_taille = size/20;
			tab= new byte[size];
		}
			
		
		for(int i = 0; i < secu_taille;i++)
		{
			
			byte tab_g[] = new byte[24];
			for(int j = 0; j < 20; j++) {// recopie graine
				tab_g[j] = g[j];
			}
			for(int j = 20; j < 23;j++)
				tab_g[j] = 0x00;
			tab_g[23] = (byte) i;
			
			try {
				
				MessageDigest shasha = MessageDigest.getInstance("SHA-1");
				shasha.update(tab_g);
				byte resume[] = shasha.digest(); 
				for(int j = i*20; j < i*20+20;j++)
					tab[j] = resume[j - 20*i];
					
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				System.out.println("probleme");
				e.printStackTrace();
				System.exit(1);
			}
			
			
			
			
		}
		
		
		return tab;
		
	}
	public byte[] bourragePKCS1() {
		
		BigInteger bmess = new BigInteger(K,16);
		
		
		byte tab_mess[] = bmess.toByteArray();
		if(tab_mess.length < 0||tab_mess.length >86) {
			System.out.println("erreur message trop long");
			System.exit(1);
		}
		String  bloc_lettre="DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";//40
		byte bour_av_mask[] = new byte[107];
		int index =0;
		for(int i = 0; i < 40; i+=2) {
			
			int octet = Integer.parseInt(bloc_lettre.substring(i,i+2),16);
			if(octet > 255) {
				System.out.println("probleme transformation hexa to int ");
				System.exit(1);
			}
			//System.out.println("result "+octet);
			bour_av_mask[index++] = (byte)octet;
			
		}
		int rest =  107 - tab_mess.length;
		
		for(int i = 20; i < rest-1;i++ )
			bour_av_mask[i] = 0x00;
		
		bour_av_mask[rest-1]= 0x01;
		
		for(int i = rest; i < 107;i++ ) {
			bour_av_mask[i] = tab_mess[i-rest];
		}
		
		//graine
		byte graine[] = new byte[20];
		Random rn = new Random();
		for(int i = 0; i < 20;i++ )
			graine[i] = (byte)rn.nextInt(256);
		
		byte mask_for_mess[] = MGF(graine,107);
		
		
	
		byte after_mask_mess[] = new byte[107];
	
		
		
		for(int i = 0; i < 107; i++) {
			
		
			after_mask_mess[i] = (byte) (bour_av_mask[i]^mask_for_mess[i]); 
		}
		
		byte mask_for_seek[] = MGF(after_mask_mess,20);
		byte after_mask_seek[] = new byte[20];
		
		for(int i = 0; i < 20; i++) {
			
			
			after_mask_seek[i] = (byte) ( mask_for_seek[i]^after_mask_mess[i]); 
		}
		
		
		byte bour_task[]= new byte[128];

		bour_task[0] = 0x00;
		
		for(int i = 0 ; i < 20;i++)
			bour_task[i+1] = after_mask_seek[i];
		
		for(int i = 0; i < 107;i++)
			bour_task[i+21] = after_mask_mess[i];
		
		return bour_task;
	}
	
	
	
	public static  BigInteger os2ip(byte tab[]) { 
		BigInteger code = BigInteger.ZERO; 
		byte encodage[] = tab;
		for (int i =0;i < encodage.length ; i++) {
	
		// On utilise la methode de Horner 
		code = code.multiply(BigInteger.valueOf(256)); 
		int chiffre = encodage[i]; // chiffre peut etre negatif! 
		if ( chiffre <0)chiffre+=256; // car les Bytes sont signes en Java! // 
		//int chiffre = encodage[i] & 0xFF ; // Equivalent plus simple!
		code = code.add(BigInteger.valueOf(chiffre)); 
		}
		return code;
	}
	
	
	public static byte[] i2osp(BigInteger code) { 
		int longueur = 128; // C est la taille du tableau decodage 
		BigInteger tmp = code; 
		byte decodage[] =  new byte[longueur];
		for (int i = longueur - 1;i>=0 ; i--) { 
			decodage[i]=(byte) tmp.mod(BigInteger.valueOf(256)).intValue() ; 
			tmp = tmp.divide(BigInteger.valueOf(256));
			} 
		return decodage;
	}
	

	public static void main(String args[]){
	    Poc obj1 = new Poc(16);
	    byte[] tab_bour;
	    BigInteger m;
	    try {
			FileOutputStream fos = new  FileOutputStream(args[0]);
			tab_bour = obj1.bourragePKCS1();
			m = os2ip(tab_bour);
			m.modPow(e,n);
			fos.write(i2osp(m));
			fos.close();
		} catch ( IOException e) {
			// TODO Auto-generated catch block
			System.out.println("probleme ecriture bourragePCKS1");
			e.printStackTrace();
		}
	    try {
	    	
	        BufferedWriter writer = new BufferedWriter(new FileWriter(args[1]));
	        writer.write(obj1.K);
	         
	        writer.close();
		
		} catch ( IOException e) {
			// TODO Auto-generated catch block
			System.out.println("probleme ecriture bourragePCKS1");
			e.printStackTrace();
		}
	    
	   
		System.out.println("fin partie java");
	}
}
