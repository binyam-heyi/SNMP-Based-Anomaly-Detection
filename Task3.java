/*This class uses use Z-score and Tukeys method try to detect additional anomalies.*/
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Random;
import java.util.Set;
import java.util.Arrays;
import java.util.Collections;
public class Task3
{
static String ip = "192.168.15.10";
//we choose to implement in
String[] getinput = new String[10];
public static final String inOctets_OID[] = { ".1.3.6.1.2.1.2.2.1.10.1",
				".1.3.6.1.2.1.2.2.1.10.2" };
public static final String ifInUcastPkts_OID[] = {
			".1.3.6.1.2.1.2.2.1.11.1", ".1.3.6.1.2.1.2.2.1.11.2" };
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

		
			double[][] Samplepoints = new double[2][timeSeries];

			long Time_Start = new Date(System.currentTimeMillis()).getTime();
			System.out.println("Sampling started at: " + dateFormat(Time_Start));
	              System.out.println("Sample seq number   ||         Duration   "  );
                     System.out.println("========================================== "  );

			long[] TimeArray = new long[timeSeries];
			for (int k = 0; k < timeSeries; k++)
                  {
				try {

					double[][] temp = takingSamples(hostListIps, parameters);
					Samplepoints[0][k] = temp[0][0];
                                   Samplepoints[1][k] = temp[1][0];
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
						+ Samplepoints[0][k] + ""+Samplepoints[1][k]);
                             }
                            else
                              {
                              System.out.println("Sample No. " + k + " polled with in time= "
						+ (TimeArray[k] - TimeArray[k-1])  + "sec =  "
						+ Samplepoints[0][k] + ""+Samplepoints[0][k]);

                               }
				if (deltaT > 2)
				{
					deltaT = deltaT - 2; // 2 sec Accounted for time taken in samping
				      sleep(deltaT);
				}
			}
			/*System.out.println("Total Sampling time for "+timeSeries+
			 " Samples = "+((new
			 Date(System.currentTimeMillis()).getTime())-Time_Start) );
                      //To calculate overall global state we can call the function overAllGlobal();
                      System.out.println("Caluculating Global States");
                      System.out.println("===================================");
                      //Array for holding the global states
			 double[][]globalStates= new double[2][timeSeries-1];
                      double[][]sort=new double[2][timeSeries-1];
                      double[][]hold=new double[2][timeSeries-1];
                      double[][]quartiles=new double[2][3];
                      double mean[][]=new double[2][1];
                      double SD[][]=new double[2][1];
                        
                        double Q1,Q2,Q3;
                         globalStates=overAllGlobal(TimeArray,Samplepoints,timeSeries);
                                int globalPoints=timeSeries-1;
                           hold=copy(globalStates,globalPoints);
                         sort=sortingGlobal(hold,globalPoints);
                          mean=calculateMean(globalStates,globalPoints);
                          quartiles=calculateQuartiles(sort,globalPoints);
                          // Q2=calculateMedian(sort);
                         // quartiles=calculateQuartiles(sort);
                         System.out.println("The mean of the sample      " + mean);
                          SD=calculateSD(globalStates,globalPoints,mean);
                          System.out.println("The SD of the sample      " + SD);
                         // System.out.println("The Median of the sample      " + Q2);
                        System.out.println("The quartiles of the sample      " + quartiles[0] + quartiles[1] +  quartiles[2]);
                         //Detectin oultliers 
                           outliersSD(globalStates,globalPoints,mean,SD);
                           outliersTukeys(sort,quartiles,globalPoints);*/
                        
			

		}
//This function takes sample of X at the interval defined by deltaT
public static double[][] takingSamples(ArrayList<String> RouterIP,
			String[] parameters) {
		snmpFunction func = new snmpFunction();
		ArrayList<String> inOctetsArray = new ArrayList<String>();
              ArrayList<String> Ucastarray = new ArrayList<String>();
              double[][] Final = new double[2][1];
		double TotalInOct = 0,TotalUnIP=0;
		for (int c = 0; c < RouterIP.size(); c++) {
			parameters[8] = RouterIP.get(c);
			parameters[9] = inOctets_OID[0];
                     //Adding to the inOctatesArrayList.(s(i));
			inOctetsArray.add(func.MySnmpGet(parameters));
                    //Adding to the ifInOctates
                       parameters[9] = ifInUcastPkts_OID[1];
                       Ucastarray.add(func.MySnmpGet(parameters));
                       
		}

		for (int sumC = 0; sumC < inOctetsArray.size(); sumC++) {
			TotalInOct = TotalInOct
					+ Double.parseDouble(snmpParse(inOctetsArray.get(sumC),
						"Counter: "));
                      TotalUnIP = TotalUnIP
					+ Double.parseDouble(snmpParse(Ucastarray.get(sumC),
						"Counter: "));

				}

		Final[0][0]=TotalInOct;
              Final[0][1]=TotalUnIP;
		return Final;

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
public static double[][] overAllGlobal(long[] time,double [][] points, int NumberofPoints) {
			double[][] sampDiff = new double[2][NumberofPoints - 1];
                     double[] timeDiff = new double[NumberofPoints - 1];
                     double[][] global = new double[2][NumberofPoints - 1];
			for (int k = 0; k < NumberofPoints - 1; k++) {
				sampDiff[0][k] = Math.abs(points[0][k + 1] - points[0][k]);
                            sampDiff[1][k] = Math.abs(points[1][k + 1] - points[1][k]);
				timeDiff[k] = Math.abs(time[k + 1] - time[k]);
                            global[0][k] = (sampDiff[0][k]/timeDiff[k]);
                            global[1][k] = (sampDiff[1][k]/timeDiff[k]);

				 System.out.println("global State :" + k + " = " + global[0][k]+" "+global[1][k] );
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
    public static double[][] calculateMean(double[][] globalStates,int globalPoints)
{   
     double  sum=0;
      double sum1=0;
           double[][] FinalAvg = new double[2][1];
        for(int i=0;i<globalPoints;i++)
             {
              sum+=globalStates[0][i];
              sum1+=globalStates[1][i];
              }
              FinalAvg[0][0]=(sum/globalPoints);
              FinalAvg[1][0]=(sum1/globalPoints);

              return FinalAvg;     

} 
//For calculating the standard Deviation
public static double[][] calculateSD(double[][] globalStates,int globalPoints,double[][] mean)
{ 
      double sum=0;
      double sum1=0;
        double[][] FinalAvg = new double[2][1];

     for(int i=0;i<globalPoints;i++)
       {
        sum+=Math.pow((globalStates[0][i]-mean[0][i]),2);
        sum1+=Math.pow((globalStates[0][i]-mean[1][i]),2);
        }
      FinalAvg[0][0]=sum/(globalPoints-1);
      FinalAvg[1][0]=sum/(globalPoints-1);
        return FinalAvg;
    
}
//for calculating median
public static double calculateMedian(ArrayList<Double> values)
{ 
       if (values.size() % 2 == 1)
	return values.get((values.size()+1)/2-1);
    else
    {
	double lower = values.get(values.size()/2-1);
	double upper = values.get(values.size()/2);
 
	return (lower + upper) / 2.0;
    }	
}

//for detecting outliers
public static void outliersSD(double[][] globalStates,int globalPoints,double[][] mean,double[][] SD)
{ 

      double upperBound=mean[0][0]+3*SD[0][0];
      double upperBound1=mean[1][0]+3*SD[1][0];
      double lowerBound=mean[0][0]-3*SD[0][0];
      double lowerBound1=mean[1][0]-3*SD[1][0];


           int count=0;
       int uct=0;
 System.out.println("  UpperBound  "   +                    "upperBound " );
 System.out.println("[" + upperBound + "," +   lowerBound +"]" );
 
     for(int i=0;i< globalPoints;i++)
       {   
         if((globalStates[0][i]<=lowerBound) || (globalStates[0][i]>=upperBound)) 
           {
            System.out.println("Outlier Detected on GlobalStatete Inoc  " + i +" With Value " + globalStates[0][i]);
             count++ ;      
            }
            if((globalStates[1][i]<=lowerBound1) || (globalStates[1][i]>=upperBound1)) 
           {
            System.out.println("Outlier Detected on GlobalState unip " + i +" With Value " + globalStates[0][i]);
             uct++ ;      
            }

        }
       System.out.println("Total Number of in Oct Outliers  " + count+
       "Total Number of in Unip Outliers  "+ uct );
}
//Sorting gloabal arrays
public static double[][] sortingGlobal(double[][]intArray,int points)
{

               int n = points;
                double temp = 0;
               
                for(int i=0; i < n; i++)
            {
                        for(int j=1; j < (n-i); j++)
                   {
                               
                                if(intArray[0][j-1] > intArray[0][j])
                                 {
                                        //swap the elements!
                                        temp = intArray[0][j-1];
                                        intArray[0][j-1] = intArray[0][j];
                                        intArray[0][j] = temp;
                                }
                               if(intArray[1][j-1] > intArray[1][j])
                                 {
                                        //swap the elements!
                                        temp = intArray[1][j-1];
                                        intArray[1][j-1] = intArray[1][j];
                                        intArray[1][j] = temp;
                                }

                   } 
          }
System.out.println("Sorted");
for(int i=0; i < n; i++){
                        System.out.println(intArray[0][i] + " "+intArray[1][i]);
                }

return intArray;
}
public static double[][]copy(double[][] intArray,int points)
{ 
 int len=points;
 double[][] hold1=new double[2][len]; 
 for(int i=0;i<len;i++)
{
  hold1[0][i]=intArray[0][i];
  hold1[1][i]=intArray[0][i];
}
System.out.println( " Copied");
 for(int i=0; i < len; i++)
             {
                        System.out.println(intArray[0][i] + " "+intArray[1][i]);
             }
return hold1;
}
public static double[][] calculateQuartiles(double[][] array,int points)
{
   double[][] FinalAvg = new double[2][3];
   ArrayList<Double> values = new ArrayList<Double>();
   ArrayList<Double> lowerHalf = new ArrayList<Double>();
   ArrayList<Double> upperHalf = new ArrayList<Double>();
   ArrayList<Double> values1 = new ArrayList<Double>();
   ArrayList<Double> lowerHalf1 = new ArrayList<Double>();
   ArrayList<Double> upperHalf1 = new ArrayList<Double>();
    for(int i=0;i<points-1;i++)
       values.add(array[0][i]);
   double median = calculateMedian(values);
 
    lowerHalf = GetValuesLessThan(values, median, true);
    upperHalf = GetValuesGreaterThan(values, median, true);
    FinalAvg[0][0]=calculateMedian(lowerHalf);
    FinalAvg[0][1]=median;
    FinalAvg[0][2]=calculateMedian(upperHalf);
      for(int i=0;i<points-1;i++)
       values1.add(array[1][i]);
   double median1 = calculateMedian(values1);
    lowerHalf1 = GetValuesLessThan(values, median, true);
    upperHalf1 = GetValuesGreaterThan(values, median, true);
     FinalAvg[1][0]=calculateMedian(lowerHalf1);
    FinalAvg[1][1]=median1;
    FinalAvg[1][2]=calculateMedian(upperHalf1);

   return FinalAvg;  
}

public static ArrayList<Double> GetValuesGreaterThan(ArrayList<Double> values, double limit, boolean orEqualTo)
{
    ArrayList<Double> modValues = new ArrayList<Double>();
 
    for (double value : values)
        if (value > limit || (value == limit && orEqualTo))
            modValues.add(value);
 
    return modValues;
}
public static ArrayList<Double> GetValuesLessThan(ArrayList<Double> values, double limit, boolean orEqualTo)
{
    ArrayList<Double> modValues = new ArrayList<Double>();
 
    for (double value : values)
        if (value < limit || (value == limit && orEqualTo))
            modValues.add(value);
 
    return modValues;
}
public static void outliersTukeys(double[][] array,double[][]quar,int points)
{
    double IQR=quar[0][2]-quar[0][0];
    double IQR1=quar[1][2]-quar[0][0];
System.out.println("IQR"+IQR);
    double upperFence=quar[0][2]+1.5*IQR;
    double lowerFence=quar[0][0]-1.5*IQR;
    double upperFence1=quar[1][2]+1.5*IQR1;
    double lowerFence1=quar[1][0]-1.5*IQR1;

    int count=0;
    int uip=0;
for(int i=0;i< array.length;i++)
       {   
         if((array[0][i]<=lowerFence) || (array[0][i]>=upperFence)) 
           {
            System.out.println("Outlier Detected on GlobalState inoct " + i +" With Value " + array[0][i]);
             count++ ;      
            }
         if((array[1][i]<=lowerFence) || (array[1][i]>=upperFence)) 
           {
            System.out.println("Outlier Detected on GlobalState uip " + i +" With Value " + array[1][i]);
             uip++ ;      
            }

        }
       System.out.println("Total Number of Outliers inoct " + count +
                           "Total Number of Outliers uip " + uip );


}


}

