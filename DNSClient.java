
import java.io.*;
import java.net.*;
import java.util.*;

class DNSClient {

    private static final int TYPE_A = 0x0001;
    private static final int TYPE_NS = 0x0002;
    private static final int TYPE_CNAME = 0x0005; //This can be received but not queried
    private static final int TYPE_MX = 0x000f;
    private static final int CLASS_IN = 0x0001;

    // Helper class to hold query result
    private static final class QueryResult {

        final int transactionId;
        final byte[] packet;

        QueryResult(int id, byte[] pkt) {
            this.transactionId = id;
            this.packet = pkt;
        }
    }

    // Helper class to hold send result
    private static final class SendResult {

        final int transactionId;
        final byte[] response;
        final long elapsedMillis;
        final int retriesUsed;

        SendResult(int id, byte[] resp, long ms, int retries) {
            this.transactionId = id;
            this.response = resp;
            this.elapsedMillis = ms;
            this.retriesUsed = retries;
        }
    }

    // Helper class to hold name result after parsing response packet
    private static final class NameResult {
        String name;
        int nextOffset;

        NameResult(String n, int o) {
            this.name = n;
            this.nextOffset = o;
        }
    }

    // Helper function to check if a string is numeric
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

    //Helper function converting IP string into InetAddress; return null if invalid
    public static InetAddress convertToInetAddress(String ip) {
        String[] parts = ip.split("\\.");
        //IPv4 should exactly 4 parts since 32-bit 
        if (parts.length != 4) {
            System.err.println("ERROR \t Invalid IPv4 address format.");
            System.exit(1);
        }
        //addr = [0, 0, 0, 0]
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            try {
                int part = Integer.parseInt(parts[i]);
                // Each part must be in range 0-255
                if (part < 0 || part > 255) {
                    System.err.println("ERROR \t Each part of the address must be between 0-255.");
                    System.exit(1);
                }
                // Ipv4 addr is 32-bit, each octet is 8 bits and ranges from 0-255 (2^8 = 256)
                bytes[i] = (byte) part;
            } catch (NumberFormatException e) {
                System.err.println("ERROR \t Each part of the address must be numeric.");
                System.exit(1);
            }
        }
        try {
            return InetAddress.getByAddress(bytes);
        } catch (UnknownHostException e) {
            System.err.println("ERROR \t Invalid IP address.");
            System.exit(1);
            return null; // Unreachable, but required by the compiler
        }
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
                if (!isNumeric(args[i])) {
                    System.err.println("ERROR \t Timeout must be a number");
                    System.exit(1);
                }
                timeout = args[i];
            } else if (args[i].equals("-r")) {
                i++;
                if (i >= args.length) {
                    System.err.println("ERROR \t Missing max retries value");
                    System.exit(1);
                }
                if (!isNumeric(args[i])) {
                    System.err.println("ERROR \t Max retries must be a number");
                    System.exit(1);
                }
                maxRetries = args[i];
            } else if (args[i].equals("-p")) {
                i++;
                if (i >= args.length) {
                    System.err.println("ERROR \t Missing port value");
                    System.exit(1);
                }
                if (!isNumeric(args[i])) {
                    System.err.println("ERROR \t Port must be a number");
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
        return new String[]{timeout, maxRetries, port, queryType, server, name};
    }

    // Convert query type string to its corresponding integer value
    private static int qtypeFromString(String s) {
        if (s == null) {
            return TYPE_A;
        }
        switch (s.toUpperCase(Locale.ROOT)) {
            case "A":
                return TYPE_A;
            case "NS":
                return TYPE_NS;
            case "MX":
                return TYPE_MX;
            default:
                return TYPE_A; // default to A if unknown
        }
    }

    // Encode domain name into DNS format
    private static byte[] encodeName(String name) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        String[] labels = name.split("\\.");
        for (String label : labels) {
            // Labels can only be at most 63 octets long
            if (label.length() == 0 || label.length() > 63) {
                throw new IOException("Invalid label length in name: " + label);
            }
            baos.write(label.length());
            baos.write(label.getBytes("UTF-8"));
        }
        baos.write(0x00);
        return baos.toByteArray();
    }

    // Build DNS query packet
    private static QueryResult buildQuery(String qname, String queryTypeStr) {
        // Generate a random transaction ID
        int transactionId = new Random().nextInt(65536); // 0 to 65535 since it's 16-bit
        //RD = 1 since we want recursion
        int flags = 0x0100;
        int qdcount = 1, ancount = 0, nscount = 0, arcount = 0;

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            // Building the header
            dos.writeShort(transactionId & 0xFFFF); // we want to ensure that it's lower 16-bits
            dos.writeShort(flags & 0xFFFF);
            dos.writeShort(qdcount);
            dos.writeShort(ancount);
            dos.writeShort(nscount);
            dos.writeShort(arcount);

            // Building the question
            dos.write(encodeName(qname));
            dos.writeShort(qtypeFromString(queryTypeStr) & 0xFFFF);
            dos.writeShort(CLASS_IN);

            byte[] packet = baos.toByteArray();
            return new QueryResult(transactionId, packet);
        } catch (IOException e) {
            System.err.println("ERROR\tFailed to build DNS query: " + e.getMessage());
            System.exit(1);
            return null;
        }
    }

    private static SendResult sendQuery(InetAddress serverAddr,
            int port,
            int timeoutSeconds,
            int maxRetries,
            String qname,
            String queryTypeStr) {
        int retries = 0;
        while (retries < maxRetries) {
            DatagramSocket sock = null;
            try {
                sock = new DatagramSocket();
                // Set socket timeout in milliseconds
                sock.setSoTimeout(Math.max(0, timeoutSeconds) * 1000);

                // Build query packet
                QueryResult q = buildQuery(qname, queryTypeStr);
                DatagramPacket sendPacket = new DatagramPacket(q.packet, q.packet.length, serverAddr, port);

                //start time in nanoseconds 
                long startNs = System.nanoTime();
                sock.send(sendPacket);

                //Buffer to store data received from the server
                byte[] buffer = new byte[1024];
                DatagramPacket receivedPacket = new DatagramPacket(buffer, buffer.length);
                sock.receive(receivedPacket);
                long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;

                // Copy only the received data without unused space 
                byte[] resp = Arrays.copyOf(receivedPacket.getData(), receivedPacket.getLength());
                return new SendResult(q.transactionId, resp, elapsedMs, retries);

            } catch (SocketTimeoutException te) {
                System.out.println("Timeout occurred. Retrying " + (retries + 1) + "/" + maxRetries + "...");
                retries++;
            } catch (IOException ioe) {
                System.err.println("ERROR\tSocket error: " + ioe.getMessage());
                System.exit(1);
            } finally {
                if (sock != null) {
                    sock.close();
                }
            }
        }
        System.err.println("ERROR\tMaximum number of retries " + maxRetries + " exceeded");
        System.exit(1);
        return null; // unreachable
    }

    private static NameResult parseName(byte[] name, int offset) {
        StringBuilder sb = new StringBuilder();
        int pos = offset;
        boolean jumped = false;
        int jumpPos = -1;

        while (true) {
            int length = name[pos] & 0xFF;
            // Checks if there is a pointer for compression
            if ((length & 0xC0) == 0xC0) {
                int pointer = ((length & 0x3F) << 8) | (name[pos + 1] & 0xFF);
                if (!jumped) {
                    jumpPos = pos + 2; // where we’d continue if we didn’t jump
                }
                pos = pointer;
                jumped = true;
            }
            // End of name
            else if (length == 0) {
                pos++;
                break;
            } 
            // Normal label
            else {
                pos++;
                if (sb.length() > 0) sb.append(".");
                for (int i = 0; i < length; i++) {
                    sb.append((char)(name[pos++] & 0xFF));
                }
            }
        }
            int next = jumped ? jumpPos : pos;
    return new NameResult(sb.toString(), next);
    }

    private static int parseRecords(byte[] response, int pos, int count, String authStr, String sectionName) {
        for (int i = 0; i < count; i++) {
            NameResult rrName = parseName(response, pos);
            pos = rrName.nextOffset;

            int type = ((response[pos] & 0xFF) << 8) | (response[pos + 1] & 0xFF);
            int clazz = ((response[pos + 2] & 0xFF) << 8) | (response[pos + 3] & 0xFF);
            long ttl = ((response[pos + 4] & 0xFFL) << 24) | ((response[pos + 5] & 0xFFL) << 16)
                    | ((response[pos + 6] & 0xFFL) << 8) | (response[pos + 7] & 0xFFL);
            int rdLength = ((response[pos + 8] & 0xFF) << 8) | (response[pos + 9] & 0xFF);
            pos += 10;

            switch (type) {
                case TYPE_A:
                    if (rdLength == 4) {
                        String ip = (response[pos] & 0xFF) + "." +
                                    (response[pos + 1] & 0xFF) + "." +
                                    (response[pos + 2] & 0xFF) + "." +
                                    (response[pos + 3] & 0xFF);
                        System.out.println("IP\t" + ip + "\t" + ttl + "\t" + authStr);
                    } else {
                        System.err.println("ERROR\tUnexpected RDLENGTH for A record: " + rdLength);
                    }
                    pos += rdLength;
                    break;

                case TYPE_CNAME:
                    NameResult cname = parseName(response, pos);
                    System.out.println("CNAME\t" + cname.name + "\t" + ttl + "\t" + authStr);
                    pos = cname.nextOffset;
                    break;

                case TYPE_NS:
                    NameResult ns = parseName(response, pos);
                    System.out.println("NS\t" + ns.name + "\t" + ttl + "\t" + authStr);
                    pos = ns.nextOffset;
                    break;

                case TYPE_MX:
                    int preference = ((response[pos] & 0xFF) << 8) | (response[pos + 1] & 0xFF);
                    NameResult mx = parseName(response, pos + 2);
                    System.out.println("MX\t" + mx.name + "\t" + preference + "\t" + ttl + "\t" + authStr);
                    pos = mx.nextOffset;
                    break;

                default:
                    System.out.println("ERROR\tUnsupported TYPE (" + type + ") in " + sectionName);
                    pos += rdLength;
                    break;
            }
        }
        return pos;
    }


    private static void parseAnswer(byte[] response, int expectedId) {
        // Parse header
        int id = ((response[0] & 0xFF) << 8) | (response[1] & 0xFF);
        int flags = ((response[2] & 0xFF) << 8) | (response[3] & 0xFF);
      

        if (id != expectedId) {
            System.err.println("ERROR\tResponse ID does not match the query ID");
            System.exit(1);
        }

        // decode flag bits
        int qr = (flags >> 15) & 0x1;   // Query=0, Response=1
        if (qr != 1) {
            System.err.println("ERROR\tQR bit is incorrect (Expected 1)");
            System.exit(1);
        }
        int opcode = (flags >> 11) & 0xF; // usually 0 (standard query)
        int aa = (flags >> 10) & 0x1; // authoritative answer
        
        int tc = (flags >> 9) & 0x1; // truncated
        int rd = (flags >> 8) & 0x1; // recursion desired
        int ra = (flags >> 7) & 0x1; // recursion available
        if (ra != 1) {
            System.err.println("ERROR\tServer does not support recursive queries");
        }
        int z = (flags >> 4) & 0x7; // reserved, must be 0
        int rcode = (flags) & 0xF; // response code

        switch (rcode) {
            case 0:
                break;
            case 1:
                System.err.println("ERROR\tFormat error: the name server was unable to interpret the query");
                System.exit(1);
                break;
            case 2:
                System.err.println("ERROR\tServer failure: the name server was unable to process this query due to a problem with the name server");
                System.exit(1);
                break;
            case 3:
                System.out.println("NOTFOUND");
                System.exit(0);
                break;
            case 4:
                System.err.println("ERROR\tNot implemented: the name server does not support the requested kind of query");
                System.exit(1);
                break;
            case 5:
                System.err.println("ERROR\tRefused: the name server refuses to perform the requested operation for policy reasons");
                System.exit(1);
                break;
            default:
                System.err.println("ERROR\tUnexpected RCODE: " + rcode);
                System.exit(1);
        }

        int qdCount = ((response[4] & 0xFF) << 8) | (response[5] & 0xFF);
        int anCount = ((response[6] & 0xFF) << 8) | (response[7] & 0xFF);
        int nsCount = ((response[8] & 0xFF) << 8) | (response[9] & 0xFF);
        int arCount = ((response[10] & 0xFF) << 8) | (response[11] & 0xFF);

        int pos = 12; // after header

        // Skip over Question section
        for (int q = 0; q < qdCount; q++) {
            NameResult qname = parseName(response, pos);
            pos = qname.nextOffset;
            pos += 4; // skip QTYPE + QCLASS
        }

        // Utility for auth string
        String authStr = (aa == 1) ? "auth" : "nonauth";

        // Answer Section
        if (anCount > 0) {
            System.out.println("***Answer Section (" + anCount + " records)***");
            pos = parseRecords(response, pos, anCount, authStr, "Answer");
        }

        // Authority Section
        if (nsCount > 0) {
            System.out.println("***Authority Section (" + nsCount + " records)***");
            pos = parseRecords(response, pos, nsCount, authStr, "Authority");
        }

        // Additional Section
        if (arCount > 0) {
            System.out.println("***Additional Section (" + arCount + " records)***");
            pos = parseRecords(response, pos, arCount, authStr, "Additional");
        }
    }
        

    public static void main(String args[]) throws Exception {

        String[] params = getArguments(args);

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
        String server = params[4];
        String name = params[5];

        InetAddress serverAddress = convertToInetAddress(server);

        // Print parsed info
        System.out.println("DnsClient sending request for " + name);
        System.out.println("Server: " + server);
        System.out.println("Request type: " + queryType);

        //Sending the query
        SendResult r = sendQuery(serverAddress, port, timeout, maxRetries, name, queryType);

        //Logging the result
        System.out.println("Transaction ID of query:" + r.transactionId);
        System.out.println("Received " + r.response.length + " bytes in " + r.elapsedMillis + " ms"
                + " (retries used: " + r.retriesUsed + ")");
        System.out.println("Response received after " + r.elapsedMillis + "ms (" + r.retriesUsed + " retries)");

        parseAnswer(r.response, r.transactionId);
    }
};
