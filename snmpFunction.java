import java.util.Enumeration;

import com.adventnet.snmp.snmp2.SnmpAPI;
import com.adventnet.snmp.snmp2.SnmpException;
import com.adventnet.snmp.snmp2.SnmpGroup;
import com.adventnet.snmp.snmp2.SnmpOID;
import com.adventnet.snmp.snmp2.SnmpPDU;
import com.adventnet.snmp.snmp2.SnmpSession;
import com.adventnet.snmp.snmp2.SnmpVarBind;
import com.adventnet.snmp.snmp2.UDPProtocolOptions;
import com.adventnet.snmp.snmp2.usm.USMUtils;
//This class helps to walk and go through the network using //SNMP OIDS 
public class snmpFunction {

	static SnmpPDU WalkResponses[] = null;
	static int counter;
	String test[];
	String sumtext;

	public snmpFunction() {
		sumtext = "";
		test = null;
		counter = 0;
		WalkResponses = null;

		// TODO Auto-generated constructor stub
	}

	// SNMPWALK Implementation

	public String MySnmpWalk(String args[]) {

		// Take care of getting options
		String usage = "\nsnmpwalk [-d] [-v version(v1,v2,v3)] \n"
				+ "[-c community] [-p port] [-r retries] \n"
				+ "[-t timeout] [-u user] [-a auth_protocol] \n"
				+ "[-w auth_password] [-s priv_password] \n"
				+ "[-n contextName] [-i contextID] \n"
				+ "[-DB_driver database_driver]\n" + "[-DB_url database_url]\n"
				+ "[-DB_username database_username]\n"
				+ "[-DB_password database_password]\n"
				+ "[-pp privProtocol(DES/AES-128/AES-192/AES-256/3DES)]\n"
				+ "host OID\n";

		String options[] = { "-d", "-c", "-wc", "-p", "-r", "-t", "-m", "-v",
				"-u", "-a", "-w", "-s", "-n", "-i", "-DB_driver", "-DB_url",
				"-DB_username", "-DB_password", "-pp" };

		String values[] = { "None", null, null, null, null, null, "None", null,
				null, null, null, null, null, null, null, null, null, null,
				null };

		ParseOptions opt = new ParseOptions(args, options, values, usage);
		if (opt.remArgs.length != 2) {
			opt.usage_error();
		}

		// Start SNMP API
		SnmpAPI api;
		api = new SnmpAPI();
		if (values[0].equals("Set")) {
			api.setDebug(true);
		}

		// Open session
		SnmpSession session = new SnmpSession(api);

		int PORT = 3;

		// set remote Host and remote Port
		UDPProtocolOptions ses_opt = new UDPProtocolOptions();
		ses_opt.setRemoteHost(opt.remArgs[0]);
		if (values[PORT] != null) {
			try {
				ses_opt.setRemotePort(Integer.parseInt(values[PORT]));
			} catch (Exception exp) {
				System.out.println("test0");
				System.out.println("Invalid port: " + values[PORT]);
				System.exit(1);

			}
		}
		session.setProtocolOptions(ses_opt);
		// set the values
		SetValues setVal = new SetValues(session, values);

		if (setVal.usage_error) {
			opt.usage_error();
		}

		String driver = values[14];
		String url = values[15];
		String username = values[16];
		String password = values[17];

		if (driver != null || url != null || username != null
				|| password != null) {
			if (session.getVersion() != 3) {
				System.out
						.println("Database option can be used only for SNMPv3.");
				System.exit(1);
			}
			if (driver == null) {
				System.out.println("The Database driver name should be given.");
				System.exit(1);
			}
			if (url == null) {
				System.out.println("The Database URL should be given.");
				System.exit(1);
			}
			try {
				api.setV3DatabaseFlag(true);
				api.initJdbcParams(driver, url, username, password);
			} catch (Exception exp) {
				System.out.println("Unable to Establish Database Connection.");
				System.out.println("Please check the driverName and url.");
				System.exit(1);
			}
		}

		// Build GETNEXT request PDU
		SnmpPDU pdu = new SnmpPDU();
		pdu.setCommand(api.GETNEXT_REQ_MSG);

		// need to save the root OID to walk sub-tree
		SnmpOID oid = new SnmpOID(opt.remArgs[1]);
		int rootoid[] = (int[]) oid.toValue();
		if (rootoid == null) // if don't have a valid OID for first, exit
		{
			System.err.println("Invalid OID argument: " + opt.remArgs[1]);
			System.exit(1);
		} else {
			pdu.addNull(oid);
		}

		try {
			session.open();
		} catch (SnmpException e) {
			System.err.println("Error in open session " + e.getMessage());
			System.exit(1);
		}

		if (session.getVersion() == SnmpAPI.SNMP_VERSION_3) {
			// System.out.println("UserName = " + setVal.userName);
			pdu.setUserName(setVal.userName.getBytes());
			try {
				USMUtils.init_v3_parameters(setVal.userName, null,
						setVal.authProtocol, setVal.authPassword,
						setVal.privPassword, ses_opt, session, false,
						setVal.privProtocol);
			} catch (Exception exp) {

				System.out.println(exp.getMessage());

				session.close();
				api.close();
				return null;
				// System.exit(1);
			}
			pdu.setContextName(setVal.contextName.getBytes());
			pdu.setContextID(setVal.contextID.getBytes());
		}
		// loop for each PDU in the walk
		while (true) // until received OID isn't in sub-tree
		{
			try {
				// Send PDU and receive response PDU
				pdu = session.syncSend(pdu);
			} catch (SnmpException e) {
				System.err.println("Sending PDU" + e.getMessage());
				System.exit(1);
			}

			if (pdu == null) {
				// timeout
				System.out.println("Request timed out to: " + opt.remArgs[0]);
				// System.exit(1);
			}

			// stop if outside sub-tree
			if (!isInSubTree(rootoid, pdu)) {
				// System.out.println("Not in sub tree.");
				break;
			}

			int version = pdu.getVersion();

			if (version == SnmpAPI.SNMP_VERSION_1) {
				// check for error
				if (pdu.getErrstat() != 0) {
					System.out.println("Error Indication in response: "
							+ SnmpException.exceptionString((byte) pdu
									.getErrstat()) + "\nErrindex: "
							+ pdu.getErrindex());
					System.exit(1);
				}
				// print response pdu variable-bindings
				// System.out.println("test1"+pdu.printVarBinds());
				WalkResponses[counter] = pdu;
				// test[counter]=pdu.printVarBinds();
				sumtext = sumtext + pdu.printVarBinds();
				counter++;

			} else if ((version == SnmpAPI.SNMP_VERSION_2C)
					|| (version == SnmpAPI.SNMP_VERSION_3)) {

				Enumeration e = pdu.getVariableBindings().elements();

				while (e.hasMoreElements()) {
					int error = 0;
					SnmpVarBind varbind = (SnmpVarBind) e.nextElement();
					// check for error
					if ((error = varbind.getErrindex()) != 0) {
						System.out.println("Error Indication in response: "
								+ SnmpException.exceptionString((byte) error));
						System.exit(1);
					}
					// print response pdu variable-bindings
					// System.out.println("test2:"+pdu.printVarBinds());
					sumtext = sumtext + pdu.printVarBinds();
				}
			} else {
				System.out.println("Invalid Version Number");
			}

			// set GETNEXT_REQ_MSG to do walk
			// Don't forget to set request id to 0 otherwise next request will
			// fail
			pdu.setReqid(0);

			SnmpOID first_oid = pdu.getObjectID(0);
			pdu = new SnmpPDU();
			pdu.setCommand(api.GETNEXT_REQ_MSG);
			pdu.setUserName(setVal.userName.getBytes());
			pdu.setContextName(setVal.contextName.getBytes());
			pdu.setContextID(setVal.contextID.getBytes());
			pdu.addNull(first_oid);
		} // end of while true

		// Print the GroupCounters
		String[] localAddr = ses_opt.getLocalAddresses();
		int localPort = ses_opt.getLocalPort();
		SnmpGroup group = api.getSnmpGroup(localAddr[localAddr.length - 1],
				localPort);
		if (group != null) {
			// System.out.println("The SnmpGroup Counter values :");
			// System.out.println("snmpInPkts = " + group.getSnmpInPkts());
			// System.out.println("snmpOutPkts = " + group.getSnmpOutPkts());
			// System.out.println("snmpInGetResponses = " +
			// group.getSnmpInGetResponses());
			// System.out.println("snmpOutGetRequests = " +
			// group.getSnmpOutGetRequests());
			// System.out.println("snmpOutGetNexts = " +
			// group.getSnmpOutGetNexts());
		}

		// close session
		session.close();
		// stop api thread
		api.close();

		// System.exit(0);

		return sumtext;
	}

	/** check if first varbind oid has rootoid as an ancestor in MIB tree */
	static boolean isInSubTree(int[] rootoid, SnmpPDU pdu) {
		SnmpOID objID = (SnmpOID) pdu.getObjectID(0);
		if (objID == null) {
			return false;
		}

		int oid[] = (int[]) objID.toValue();
		if (oid == null) {
			return false;
		}
		if (oid.length < rootoid.length) {
			return false;
		}

		for (int i = 0; i < rootoid.length; i++) {
			if (oid[i] != rootoid[i]) {
				return false;
			}
		}
		return true;
	}

	private SnmpPDU[] walkresponese() {
		return WalkResponses;

	}

	// SNMPWALK END

	// SNMPGET Implementation

	public String MySnmpGet(String args[]) {
		// Take care of getting options
		String usage = "\nsnmpget [-d] [-v version(v1,v2,v3)] [-c community] \n"
				+ "[-p port] [-r retries] [-t timeout] [-u user] \n"
				+ "[-a auth_protocol] [-w auth_password] \n"
				+ "[-s priv_password] [-n contextName] [-i contextID] \n"
				+ "[-DB_driver database_driver]\n"
				+ "[-DB_url database_url]\n"
				+ "[-DB_username database_username]\n"
				+ "[-DB_password database_password]\n"
				+ "[-pp privProtocol(DES/AES-128/AES-192/AES-256/3DES)]\n"
				+ "host OID [OID] ...\n";

		String options[] = { "-d", "-c", "-wc", "-p", "-r", "-t", "-m", "-v",
				"-u", "-a", "-w", "-s", "-n", "-i", "-DB_driver", "-DB_url",
				"-DB_username", "-DB_password", "-pp" };

		String values[] = { "None", null, null, null, null, null, "None", null,
				null, null, null, null, null, null, null, null, null, null,
				null };

		ParseOptions opt = new ParseOptions(args, options, values, usage);
		if (opt.remArgs.length < 2) {
			opt.usage_error();
		}

		// Start SNMP API
		SnmpAPI api;
		api = new SnmpAPI();
		if (values[0].equals("Set")) {
			api.setDebug(true);
		}

		// Open session
		SnmpSession session = new SnmpSession(api);
		// set remote Host

		int PORT = 3;

		SnmpPDU pdu = new SnmpPDU();
		UDPProtocolOptions udpOpt = new UDPProtocolOptions();
		udpOpt.setRemoteHost(opt.remArgs[0]);
		if (values[PORT] != null) {
			try {
				udpOpt.setRemotePort(Integer.parseInt(values[PORT]));
			} catch (Exception exp) {
				System.out.println("Invalid port: " + values[PORT]);
				System.exit(1);
			}
		}
		pdu.setProtocolOptions(udpOpt);

		SetValues setVal = new SetValues(pdu, values);
		if (setVal.usage_error) {
			opt.usage_error();
		}

		String driver = values[14];
		String url = values[15];
		String username = values[16];
		String password = values[17];
		if (driver != null || url != null || username != null
				|| password != null) {
			if (pdu.getVersion() != 3) {
				System.out
						.println("Database option can be used only for SNMPv3.");
				System.exit(1);
			}
			if (driver == null) {
				System.out.println("The Database driver name should be given.");
				System.exit(1);
			}
			if (url == null) {
				System.out.println("The Database URL should be given.");
				System.exit(1);
			}
			try {
				api.setV3DatabaseFlag(true);
				api.initJdbcParams(driver, url, username, password);
			} catch (Exception exp) {
				System.out.println("Unable to Establish Database Connection.");
				System.out.println("Please check the driverName and url.");
				System.exit(1);
			}
		}

		// Build Get request PDU
		// SnmpPDU pdu = new SnmpPDU();
		pdu.setCommand(api.GET_REQ_MSG);

		// add OIDs
		for (int i = 1; i < opt.remArgs.length; i++) {
			SnmpOID oid = new SnmpOID(opt.remArgs[i]);
			if (oid.toValue() == null) {
				System.err.println("Invalid OID argument: " + opt.remArgs[i]);
			} else {
				pdu.addNull(oid);
			}
		}

		try {
			// Open session
			session.open();
		} catch (SnmpException e) {
			System.err.println("Error opening session:" + e.getMessage());
			System.exit(1);
		}

		if (pdu.getVersion() == SnmpAPI.SNMP_VERSION_3) {
			pdu.setUserName(setVal.userName.getBytes());
			try {
				USMUtils.init_v3_parameters(setVal.userName, null,
						setVal.authProtocol, setVal.authPassword,
						setVal.privPassword, udpOpt, session, false,
						setVal.privProtocol);
			} catch (SnmpException exp) {
				// System.out.println("testA");
				System.out.println(exp.getMessage());
				session.close();
				api.close();
				return null;

			}
			pdu.setContextName(setVal.contextName.getBytes());
			pdu.setContextID(setVal.contextID.getBytes());
		}

		SnmpPDU res_pdu = null;

		try {
			// Send PDU and receive response PDU
			res_pdu = session.syncSend(pdu);
		} catch (SnmpException e) {
			System.err.println("Sending PDU" + e.getMessage());
			System.exit(1);
		}
		if (res_pdu == null) {
			// timeout
			System.out.println("Request timed out to: " + opt.remArgs[0]);
			session.close();
			api.close();
			return null;
			// System.exit(1);
		}

		UDPProtocolOptions udpOptions = (UDPProtocolOptions) res_pdu
				.getProtocolOptions();
		String res = "Response PDU received from "
				+ udpOptions.getRemoteAddress() + ".";
		// print and exit
		if (res_pdu.getVersion() < 3) {
			res = res + " Community = " + res_pdu.getCommunity() + ".";
		}
		// System.out.println(res);

		// Check for error in response
		if (res_pdu.getErrstat() != 0) {
			System.err.println(res_pdu.getError());

		} else {
			// print the response pdu varbinds
			// System.out.println(res_pdu.printVarBinds());
			session.close();
			// stop api thread
			api.close();
			return res_pdu.printVarBinds();
		}

		// close session
		session.close();
		// stop api thread
		api.close();
		return null;
	}

}
