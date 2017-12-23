/*This class is used for detecting anomalies using standard deviation method. In this part the numbers of bytes that passes through a given router are measures and
compared to the mean+3*SD value and if it is greater it will be considered as an
anomaly.*/
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Random;
import java.util.Set;
public class Task2
{
static String ip = "192.168.15.10";
//we choose to implement in
String[] getinput = new String[10];
public static final String inOctets_OID[] = { ".1.3.6.1.2.1.2.2.1.10.1",
				".1.3.6.1.2.1.2.2.1.10.2" };
static ArrayList<String> hostListIps =new ArrayList<String>();
//for holding router and their interfaces
static Hashtable<Integer,routerInfo> routers= new Hashtable<Integer, routerInfo>();
//user input
static int deltaT;// user input time between polls 
static int timeSeries;
static int[] size;
//The main program takes the deltaT ,and Time Series m from the user and calls 
//The anomalyDetection() function 
public static void main(String[] args) {
			try {
				deltaT = Integer.parseInt(args[0]);
				timeSeries = Integer.parseInt(args[1]);
				} 
                    catch (Exception e) {
				System.out.println("Enter Proper Parameters");
				System.out
						.println("usuage: java Part2 deltaT(sec), timeSeries [30-60] ");
				System.exit(1);
			}
			size = new int[timeSeries];
			routersIpAddress();//for getting the routers ip address
			String newip = "192.168.15.6";

			String[] getinput = { "-v", "v3", "-u", "EP2300_student", "-w",
					"netmanagement", "-a", "MD5", newip, null };

			AnomolyDetection(getinput);

			System.exit(1);

		}
//class for hardcoded IPaddresses
public static void routersIpAddress() {

			hostListIps.add("192.168.5.6");
			hostListIps.add("192.168.6.7");
			hostListIps.add("192.168.3.5");
			hostListIps.add("192.168.2.16");
			hostListIps.add("192.168.3.8");
			hostListIps.add("192.168.2.13");
			hostListIps.add("192.168.0.11");
			hostListIps.add("192.168.10.12");
			hostListIps.add("192.168.0.2");
			hostListIps.add("192.168.9.9");
			hostListIps.add("192.168.8.1");
			hostListIps.add("192.168.9.4");
			hostListIps.add("192.168.4.14");
			hostListIps.add("192.168.12.3");
			hostListIps.add("192.168.1.10");
			hostListIps.add("192.168.1.15");

		}
public static void AnomolyDetection(String[] parameters)
		{

		
			double[] Samplepoints = new double[timeSeries];

			long Time_Start = new Date(System.currentTimeMillis()).getTime();
			System.out.println("Sampling started at: " + dateFormat(Time_Start));
	              System.out.println("Sample seq number   ||         Duration   "  );
                     System.out.println("========================================== "  );

			long[] TimeArray = new long[timeSeries];
			for (int k = 0; k < timeSeries; k++)
                  {
				try {

					double temp = takingSamples(hostListIps, parameters);
					Samplepoints[k] = temp;
					TimeArray[k] = new Date(System.currentTimeMillis()).getTime();

				} catch (Exception e) {
					System.out.println("Retrying...");
					k = k - 1;
					continue;
				}
                         
                            if(k==0)
                            {  
				System.out.println("Sample No. " + k + " polled with in time= "
						+ (TimeArray[k] - Time_Start) + "sec =  "
						+ Samplepoints[k] + "");
                             }
                            else
                              {
                              System.out.println("Sample No. " + k + " polled with in time= "
						+ (TimeArray[k] - TimeArray[k-1])  + "sec =  "
						+ Samplepoints[k] + "");

                               }
				if (deltaT > 2)
				{
					deltaT = deltaT - 2; // 2 sec Accounted for time taken in samping
				      sleep(deltaT);
				}
			}
			System.out.println("Total Sampling time for "+timeSeries+
			 " Samples = "+((new
			 Date(System.currentTimeMillis()).getTime())-Time_Start) );
                      //To calculate overall global state we can call the function overAllGlobal();
                      System.out.println("Caluculating Global States");
                      System.out.println("===================================");
                      //Array for holding the global states
			 double[]globalStates= new double[timeSeries-1];
                        double mean;
                        double SD;

                         globalStates=overAllGlobal(TimeArray,Samplepoints,timeSeries);
                           int globalPoints=timeSeries-1;
                          mean=calculateMean(globalStates,globalPoints);
                         System.out.println("The mean of the sample      " + mean);
                          SD=calculateSD(globalStates,globalPoints,mean);
                          System.out.println("The SD of the sample      " + SD);
                     //Detectin oultliers 
                           outliers(globalStates,globalPoints,mean,SD);
                        
					}
//This function takes sample of X at the interval defined by deltaT
public static double takingSamples(ArrayList<String> RouterIP,
			String[] parameters) {
		snmpFunction func = new snmpFunction();
		ArrayList<String> inOctetsArray = new ArrayList<String>();
		double TotalInOct = 0;
		for (int c = 0; c < RouterIP.size(); c++) {
			parameters[8] = RouterIP.get(c);
			parameters[9] = inOctets_OID[0];
                     //Adding to the inOctatesArrayList.(s(i));
			inOctetsArray.add(func.MySnmpGet(parameters));
		}

		for (int sumC = 0; sumC < inOctetsArray.size(); sumC++) {
			TotalInOct = TotalInOct
					+ Double.parseDouble(snmpParse(inOctetsArray.get(sumC),
						"Counter: "));
				}

		
		return TotalInOct;

	}
//This Function is used to display the current time and date
public static String dateFormat(double date_mili) {
			SimpleDateFormat dateFormat = new SimpleDateFormat("MMM dd,yyyy HH:mm");
			Date date = new Date((long) date_mili);
			return dateFormat.format(date);
		}
//for parsing purpose
public static String snmpParse(String parse, String token) {
			String[] test = parse.split(token);
			return test[1];
		}
public static double[] overAllGlobal(long[] time,double [] points, int NumberofPoints) {
			double[] sampDiff = new double[NumberofPoints - 1];
                     double[] timeDiff = new double[NumberofPoints - 1];
                     double[] global = new double[NumberofPoints - 1];
			for (int k = 0; k < NumberofPoints - 1; k++) {
				sampDiff[k] = Math.abs(points[k + 1] - points[k]);
				timeDiff[k] = Math.abs(time[k + 1] - time[k]);
                            global[k] = (sampDiff[k]/timeDiff[k]);
				 System.out.println(/*"global State :" + k + " = " +*/ global[k] );
			}
			return global;
		}
//Thread Sleep if the user inputs more than two second makes.
		public static void sleep(double period) 
            {
                     System.out.println("Thread Sleeping for " + period + " sec");
			int Sleep = (int) (period * (1000));
			try {
				Thread.sleep(Sleep);
			} catch (InterruptedException ex) {
				ex.printStackTrace();
			}
		}
//For calculating the mean of the global state
    public static double calculateMean(double[] globalStates,int globalPoints)
{   
     double  sum=0;
        for(int i=0;i<globalPoints;i++)
              sum+=globalStates[i];
              return (sum/globalPoints);     

} 
//For calculating the standard Deviation
public static double calculateSD(double[] globalStates,int globalPoints,double mean)
{ 
      double sum=0;
     for(int i=0;i<globalPoints;i++)
       {
        sum+=Math.pow((globalStates[i]-mean),2);
        }
      sum/=(globalPoints-1);
        return Math.sqrt(sum);
    
}
//for detecting outliers
public static void outliers(double[] globalStates,int globalPoints,double mean,double SD)
{ 
      double upperBound=mean+3*SD;
      double lowerBound=mean-3*SD;
      int count=0;
 System.out.println("  UpperBound  "   +                    "upperBound " );
 System.out.println("[" + upperBound + "," +   lowerBound +"]" );
 
     for(int i=0;i< globalPoints;i++)
       {   
         if((globalStates[i]<=lowerBound) || (globalStates[i]>=upperBound)) 
           {
            System.out.println("Outlier Detected on GlobalState  " + i +" With Value " + globalStates[i]);
             count++ ;      
            }
        }
       System.out.println("Total Number of Outliers  " + count );
}

}

