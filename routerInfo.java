import java.util.ArrayList;
import java.util.Vector;

// This is used to put every information on the each router discovered

public class routerInfo {
	public String hostName;
	public String engineId;
	public ArrayList<String> neighbours = new ArrayList<String>();
	public ArrayList<String> interfacesnames = new ArrayList<String>();
	public Vector<String> interfacesIPs = new Vector<String>();
	public Vector<String> nexthopvector = new Vector<String>();

	public routerInfo() {
		this.hostName = "NoName";

	}

	// Prints all the stored values e.g name,neighbours,nexthops for the given
	// router.
	public void printinfo() {
		System.out.println("Name: " + this.hostName.trim());
		System.out.println("Interfaces: " + this.interfacesnames);
		System.out.println("Interfaces IPAdds: " + this.interfacesIPs);
		System.out.println("Link Level Neighbors: " + this.nexthopvector);
		System.out.println();

	}

}
