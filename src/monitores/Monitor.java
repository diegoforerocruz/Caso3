package monitores;

import java.io.File;
import java.io.FileWriter;
import java.lang.management.ManagementFactory;
import java.util.TimerTask;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;

public class Monitor extends TimerTask {
	public void run() {
		try {
			File file = null;
			file = new File("./usoCPU.txt");
			if (!file.exists()) {
				file.createNewFile();
			}
			FileWriter fw = new FileWriter(file,true);
			fw.write(getProcessCpuLoad() + "\n");
			fw.close();
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	public static double getProcessCpuLoad() throws Exception {

		MBeanServer mbs    = ManagementFactory.getPlatformMBeanServer();
		ObjectName name    = ObjectName.getInstance("java.lang:type=OperatingSystem");
		AttributeList list = mbs.getAttributes(name, new String[]{ "ProcessCpuLoad" });

		if (list.isEmpty())     return Double.NaN;

		Attribute att = (Attribute)list.get(0);
		Double value  = (Double)att.getValue();

		// usually takes a couple of seconds before we get real values
		if (value == -1.0)      return Double.NaN;
		// returns a percentage value with 1 decimal point precision
		return ((int)(value * 1000) / 10.0);
	}
}
