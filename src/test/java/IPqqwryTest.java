import qqwry.IPSeeker;

/**
 * 测试读取数据
 * @author 
 *
 */
public class IPqqwryTest {
 
	public static void main(String[] args) {
		testqqwryWithNoConstructorArgs();
		testqqwryWithConstructorArgs();
	}
	
	private static void testqqwryWithConstructorArgs(){
		String filepath = IPSeeker.class.getResource("/config/qqwry.dat").toString();
		System.out.println(filepath);
		String path = filepath.substring(filepath.lastIndexOf(":")+1,filepath.length());
		System.out.println(path);
		IPSeeker seeker = IPSeeker.getInstance(path);
		System.out.println(seeker.getAddress("43.243.139.138"));
	}
	private static void testqqwryWithNoConstructorArgs(){
		IPSeeker seeker = IPSeeker.getInstance();
		System.out.println(seeker.getAddress("43.243.139.138"));
	}
}
