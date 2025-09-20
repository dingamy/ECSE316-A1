import java.io.*;
import java.net.*;

class DNSClient {

    private static boolean isNumeric(String strNum) {
        if (strNum == null) {
            return false;
        }
        try {
            Integer d = Integer.parseInt(strNum);
        } catch (NumberFormatException nfe) {
            return false;
        }
        return true;
    }
    // Return order: [timeout, maxRetries, port, queryType, server, name]
    private static String[] getArguments(String args[]) {
        String timeout = "5";
        String maxRetries = "3";
        String port = "53";
        String queryType = "A";
        String server = null;
        String name = null;

        //Validation flag 
        Boolean isMx = false;
        Boolean isNs = false;

        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-t")) {
                i++;
                if (i >= args.length) {
                    System.err.println("ERROR \t Missing timeout value");
                    System.exit(1);
                }
                timeout = args[i];
            } else if (args[i].equals("-r")) {
                i++;
                if (i >= args.length) {
                    System.err.println("ERROR \t Missing max retries value");
                    System.exit(1);
                }
                maxRetries = args[i];
            } else if (args[i].equals("-p")) {
                i++;
                if (i >= args.length) {
                    System.err.println("ERROR \t Missing port value");
                    System.exit(1);
                }
                port = args[i];
            } else if (args[i].equals("-mx")) {
                if (isNs) {
                    System.err.println("ERROR \t Cannot set both -mx and -ns");
                    System.exit(1);
                }
                queryType = "MX";
                isMx = true;
            } else if (args[i].equals("-ns")) {
                if (isMx) {
                    System.err.println("ERROR \t Cannot set both -mx and -ns");
                    System.exit(1);
                }
                queryType = "NS";
                isNs = true;
            } else if (args[i].startsWith("@")) {
                if (args[i].substring(1).isEmpty()) {
                    System.err.println("ERROR \t Missing server address after @");
                    System.exit(1);
                }
                server = args[i].substring(1);

                i++;
                if (i >= args.length) {
                    System.err.println("ERROR \t Missing domain name after server address");
                    System.exit(1);
                }
                name = args[i];
            } else {
                System.err.println("ERROR \t Incorrect input syntax: " + args[i]);
                System.exit(1);
            }
        }

        if (server == null || name == null) {
            System.err.println("ERROR \t Missing server address or domain name");
            System.exit(1);
        }

        return new String[] { timeout, maxRetries, port, queryType, server, name };
    }

    public static void main(String args[]) throws Exception {

        String[] params = getArguments(args);

        if (!isNumeric(params[0])) {
            System.err.println("ERROR \t Timeout must be a number");
            System.exit(1);
        }
        if (!isNumeric(params[1])) {
            System.err.println("ERROR \t Max retries must be a number");
            System.exit(1);
        }
        if (!isNumeric(params[2])) {
            System.err.println("ERROR \t Port must be a number");
            System.exit(1);
        }

        int timeout = Integer.parseInt(params[0]);
        if (timeout < 0) {
            System.err.println("ERROR \t Timeout must be positive");
            System.exit(1);
        }

        int maxRetries = Integer.parseInt(params[1]);
         if (maxRetries < 0) {
            System.err.println("ERROR \t Retries must be positive");
            System.exit(1);
        }

        int port = Integer.parseInt(params[2]);
        if (port < 1 || port > 65535) {
            System.err.println("ERROR \t Port must be in range 1-65535");
            System.exit(1);
        }
        String queryType = params[3];
        String server  = params[4];
        String name    = params[5];

        // Print parsed info
        
        System.out.println("DnsClient sending request for " + name);
        System.out.println("Server: " + server);
        System.out.println("Request type: " + queryType);

        InetAddress serverAddress = convertToInetAddress(server);
        if (serverAddress == null) {
            System.err.println("ERROR \t Invalid server IP address");
            System.exit(1);
        }

        // Create UDP socket and sending 
        System.out.println("...Preparing to send packet");
    }

    //Helper function converting IP string into InetAddress; return null if invalid
    public static InetAddress convertToInetAddress(String ip) {
        String[] parts = ip.split("\\.");
        //IPv4 should exactly 4 parts since 32-bit 
        if (parts.length != 4) {
            return null;
        }
        //addr = [0, 0, 0, 0]
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            int part;
            try {
                part = Integer.parseInt(parts[i]);
            } catch (NumberFormatException e) {
                return null;
            }
            // Ipv4 addr is 32-bit, each octet is 8 bits and ranges from 0-255 (2^8 = 256)
            if (part < 0 || part > 255) {
                return null;
            }
            bytes[i] = (byte) part;
        }
        try {
            return InetAddress.getByAddress(bytes);
        } catch (UnknownHostException e) {
            return null;
        }
    }
}