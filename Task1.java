/*The first part is discovering network topology by taking IP address form the user as an input from the user.The network topology can be traversed from this given IP
address using the SNMP traversing functions like GETreq/res, and Walk req/res.*/

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Task1 {

	static String ip = "192.168.15.10";
	String[] getInput = new String[10];
	public static final String hostName_OID = ".1.3.6.1.2.1.1.5.0";
	public static final String engineID_OID = ".1.3.6.1.6.3.10.2.1.1.0";
	public static final String ipAdEntAddr_OID = ".1.3.6.1.2.1.4.20.1.1";
	public static final String ipRouteNextHop_OID = ".1.3.6.1.2.1.4.21.1.7";
	public static final String ifDescr_OID = ".1.3.6.1.2.1.2.2.1.2";
	public static int hashcounter = 0;
	//hash Table for holding the names of the routers
	static Hashtable<Integer, routerInfo> routers = new Hashtable<Integer, routerInfo>();
	static ArrayList<String> RouterNames = new ArrayList<String>(); // Array having
																// Routers names
//A main function which intializes everything
	public static void main(String[] args) {
		String isNewIP = null;
		try {
			isNewIP = args[0];
		} catch (Exception e) {
			System.out.println("Please Enter The Proper inputs");
			System.out.println("usuage: java Part1 IpAddress");
			System.exit(1);
		}
		String[] getInput = { "-v", "v3", "-u", "EP2300_student", "-w",
				"netmanagement", "-a", "MD5", isNewIP, null };

		ArrayList<String> isTested = new ArrayList<String>();
		ArrayList<String> ipAddrLists = new ArrayList<String>();
		boolean newOne = true;
		int isChecked = 0;
		int listindex = 0;
		int size = 1;
		System.out.println("Discovering Traverse....");

		while (routers.size() < 16) {
			//Checking weather we have traversed the IP or not
			if (!isTested.contains(isNewIP) || newOne) { 
				isTested.add(isNewIP);
				getInput[8] = isNewIP;
				try {
					Traverse(getInput);
				} catch (Exception e) {
					System.out.println("Traverse Error:Lets try once more....");
					try {
						Traverse(getInput);
					} catch (Exception e2) {
						System.out.println(" Search failed:");
						System.exit(0);
					}
				}

				newOne = false;
				routerInfo temp = routers.get(isChecked);
				if (temp != null) {
					ipAddrLists.addAll(temp.nexthopvector);

					isChecked++;
					size = ipAddrLists.size();
				}

			}

			if (!(listindex < size)) {
				newOne = true;
				continue;

			}
			isNewIP = ipAddrLists.get(listindex).trim();
			listindex++;

		}

		System.out.println("Finished successfully");

		for (int i = 0; i < routers.size(); i++) {
			routers.get(i).printinfo();

		}

		System.exit(1);

	}

	//Takes an IP address from the user and traverses fron one router 
	//to other to discover a give topology
	public static void Traverse(String[] parameters) {
		Vector<String> nextHop = new Vector<String>();
		ArrayList<String> tempArray = new ArrayList<String>();
              HashSet<String> nextHopHash = new HashSet<String>();
		routerInfo router = new routerInfo();
		snmpFunction commands = new snmpFunction();

		//Traversing the topology using GET and WALK parameters

		parameters[9] = engineID_OID;
		router.engineId = snmpParseGet(commands.MySnmpGet(parameters), "STRING: ");
		parameters[9] = hostName_OID;
		router.hostName = snmpParseGet(commands.MySnmpGet(parameters), "STRING: ");
		parameters[9] = ipAdEntAddr_OID; // interfaces IP
		tempArray = parseSnmpWalk(commands.MySnmpWalk(parameters),
				"\\s192.168.+");

		router.interfacesIPs.addAll(tempArray);
		parameters[9] = ifDescr_OID;
		router.interfacesnames = parseSnmpWalk(commands
				.MySnmpWalk(parameters), "Fast.+");
		parameters[9] = ipRouteNextHop_OID;
		tempArray = parseSnmpWalk(commands.MySnmpWalk(parameters),
				"\\s192.168.+");

		nextHop.addAll(tempArray); // Removing Duplicate elements of
											// nextHop
		nextHopHash.addAll(nextHop);
		nextHop.clear();
		nextHop.addAll(nextHopHash);
		for (int y = 0; y < router.interfacesIPs.size(); y++) { // Removes
																// Routers Own
																// Interface IPs
																// from NextHop
																// vector
			for (int u = 0; u < nextHop.size(); u++) {
				if (router.interfacesIPs.get(y).equalsIgnoreCase(
						nextHop.get(u))) {
					nextHop.remove(u);
				}
			}
		}

		router.nexthopvector= nextHop;
		if (!(RouterNames.contains(router.hostName))) {
			routers.put(hashcounter, router);
			hashcounter++;
			RouterNames.add(router.hostName);
		}

	}

	// To separete the tokens which we get from SNMPGet function
	public static String snmpParseGet(String parse, String token) {
		String[] string = parse.split(token);
		return string[1];
	}

	// To Parse the SNMPWALk function.
	public static ArrayList<String> parseSnmpWalk(String parse, String pattern) {
		ArrayList<String> array = new ArrayList<String>();
		Pattern patt = Pattern.compile(pattern);
		Matcher m = patt.matcher(parse);

		while (m.find()) {

			array.add(m.group());
		}
		if (array == null) {
			System.out.println("No match found for pattern " + pattern + "in "
					+ parse);
		}
		return array;

	}
}

