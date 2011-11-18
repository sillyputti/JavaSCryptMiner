package com.dvanderbleek.miner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;


import com.google.gson.Gson;
import com.lambdaworks.crypto.SCrypt;



public class Miner {
	/**
	 * @param args
	 * @throws GeneralSecurityException 
	 * @throws IOException 
	 */
	public static void main(String[] args) throws GeneralSecurityException, IOException {
		
		 final String rpcuser ="user"; //RPC User name (set in config)
		 final String rpcpassword ="x"; //RPC Pass (set in config)
		 
		  Authenticator.setDefault(new Authenticator() {//This sets the default authenticator, with the set username and password
		      protected PasswordAuthentication getPasswordAuthentication() {
		          return new PasswordAuthentication (rpcuser, rpcpassword.toCharArray());
		      }
		  });
		  
		while(true) {
		  Work work = getwork(); //Gets the work from the server
		  String data = work.result.data; //Gets the data to hash from the work
		  String target = work.result.target;//Gets the target from the work
		  String realdata = data.substring(0, 160);
		  byte[] databyte = endianSwitch(Converter.fromHexString(realdata));
		  
     	   //Converts the target string to a byte array for easier comparison
		   byte[] targetbyte = Converter.fromHexString(target);
		   System.out.println(printByteArray(targetbyte));
		   if (doScrypt(databyte, targetbyte)) { //Calls sCrypt with the proper parameters, and returns the correct data
    		   work.result.data = printByteArray(endianSwitch(databyte))+data.substring(160, 256);
	    	   System.out.println(sendWork(work));//Send the work
		   }
		}
	}
	
	public static boolean doScrypt(byte[] databyte, byte[] target) throws GeneralSecurityException{
		//Initialize the nonce
		int[] nonce = new int[4];
		nonce[3] = databyte[76] ;
		nonce[2] = databyte[77];
		nonce[1] = databyte[78] ;
		nonce[0] = databyte[79] ;
		int ns = 0;
		int cc;
		boolean found = false;
		//Loop over and increment nonce
		while(true){
			//Set the bytes of the data to the nonce
			databyte[76] = (byte) (nonce[3]&0xff);
			databyte[77] = (byte) (nonce[2]&0xff);
			databyte[78] = (byte) (nonce[1]&0xff);
			databyte[79] = (byte) (nonce[0]&0xff);
			
			byte[] scrypted = (SCrypt.scryptJ(databyte,databyte, 1024, 1, 1, 32));//Scrypt the data with proper params
			
			if (scrypted[31] == 0) {
				cc = 30;
				while((cc>0) && (scrypted[cc] == target[cc])) cc -= 1;
				if(((0x100+scrypted[cc])&0xff) < ((0x100+target[cc])&0xff)) {
					System.out.println(printByteArray(scrypted));
					return true;
				}
			}
			
			incrementAtIndex(nonce, nonce.length-1); //Otherwise increment the nonce
			ns += 1;
			if(ns>0x4fff) {
				System.out.println("giving up on block\n");
				return false;
			}
		}
	}
	
	
	public  static void  incrementAtIndex(int[] array, int index) {
		//Short method to increment the nonce
	    if (array[index] == 255) {
	        array[index] = 0;
	        if(index > 0)
	            incrementAtIndex(array, index - 1);
	    }
	    else {
	        array[index]++;
	    }
	}
	
	
	public static String printByteArray(byte[] bites){
		//Method to convert a byte array to hex literal
		String str = "";
		for(byte bite:bites){
			str = str + (Integer.toString( ( bite & 0xff ) + 0x100, 16 /* radix */ ).substring( 1 ));
		}
		return str;
	}
	
	public static byte[] endianSwitch(byte[] bytes) {
		//Method to switch the endianess of a byte array
	   byte[] bytes2 = new byte[bytes.length];
	   for(int i = 0; i < bytes.length;  i+=4){
		   bytes2[i] = bytes[i+3];
		   bytes2[i+1] = bytes[i+2];
		   bytes2[i+2] = bytes[i+1];
		   bytes2[i+3] = bytes[i];
	   }
	   return bytes2;
	}


	public static Work getwork() throws IOException{
		//Method to getwork
		URL url = new URL("http://127.0.0.1:9332");
		URLConnection conn = url.openConnection();
	    conn.setDoOutput(true);
	    conn.setDoInput(true);
	    OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
	    String rpcreturn = "{ \"method\": \"getwork\", \"id\" : 1 }";//JSON RPC call for getting work
	    wr.write(rpcreturn);
	    wr.flush();
	    BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
	    String line;
	    
	    line = rd.readLine();
	    rd.close();
	    Gson gson = new Gson();
	    Work work = gson.fromJson(line, Work.class);//Use GSON to create a work object from the response
	    return work;  
	}

	public static String sendWork(Work work) throws IOException{
		//Very similar to getwork method
		URL url = new URL("http://127.0.0.1:9332");
		URLConnection conn = url.openConnection();
	    conn.setDoOutput(true);
	    conn.setDoInput(true);
	    OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
	    System.out.println(work.result.data);
	    String rpcreturn = "{ \"method\": \"getwork\", \"params\" : [ \"" +work.result.data+ "\" ], \"id\" : 1 }";//RPC call with the new nonced data
	    System.out.println(rpcreturn);
	    wr.write(rpcreturn);
	    wr.flush();
	    BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
	    String line;
	    line = rd.readLine();
	    rd.close();
	    return line;
	}
}
