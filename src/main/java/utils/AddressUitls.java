package utils;

import org.apache.commons.codec.binary.BinaryCodec;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.regex.Pattern;

/**
 * ipv4 、ipv6 解析工具类
 */
public class AddressUitls {

    private static final Logger logger = LoggerFactory.getLogger(AddressUitls.class);

    // 功能：判断IPv4地址的正则表达式：
    private static final Pattern IPV4_REGEX = Pattern
            .compile("^(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|[0-1]?\\d?\\d)){3}$");

    // 功能：判断标准IPv6地址的正则表达式
    private static final Pattern IPV6_STD_REGEX = Pattern.compile("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");

    // 功能：判断一般情况压缩的IPv6正则表达式
    private static final Pattern IPV6_COMPRESS_REGEX = Pattern
            .compile("^((?:[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4})*)?)::((?:([0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4})?)$");

    /*
     * 由于IPv6压缩规则是必须要大于等于2个全0块才能压缩 不合法压缩 ：
     * fe80:0000:8030:49ec:1fc6:57fa:ab52:fe69 ->
     * fe80::8030:49ec:1fc6:57fa:ab52:fe69 该不合法压缩地址直接压缩了处于第二个块的单独的一个全0块，
     * 上述不合法地址不能通过一般情况的压缩正则表达式IPV6_COMPRESS_REGEX判断出其不合法
     * 所以定义了如下专用于判断边界特殊压缩的正则表达式
     * (边界特殊压缩：开头或末尾为两个全0块，该压缩由于处于边界，且只压缩了2个全0块，不会导致':'数量变少)
     */
    // 功能：抽取特殊的边界压缩情况
    private static final Pattern IPV6_COMPRESS_REGEX_BORDER = Pattern.compile(
            "^(::(?:[0-9A-Fa-f]{1,4})(?::[0-9A-Fa-f]{1,4}){5})|((?:[0-9A-Fa-f]{1,4})(?::[0-9A-Fa-f]{1,4}){5}::)$");

    // 判断是否为合法IPv4地址
    public static boolean isIPv4Address(final String input) {
        return IPV4_REGEX.matcher(input).matches();
    }

    // 判断是否为合法IPv6地址
    public static boolean isIPv6Address(final String inputIP) {
        int NUM = 0;
        String inputStr = null;
        if (StringUtils.contains(inputIP, "%")) {
            inputStr = inputIP.substring(0, inputIP.indexOf("%"));
        } else {
            inputStr = inputIP;
        }
        for (int i = 0; i < inputStr.length(); i++) {
            if (inputStr.charAt(i) == ':') {
                NUM++;
            }
        }
        if (NUM > 7) {
            return false;
        }
        if (IPV6_STD_REGEX.matcher(inputStr).matches()) {
            return true;
        }
        if (NUM == 7) {
            return IPV6_COMPRESS_REGEX_BORDER.matcher(inputStr).matches();
        } else {
            return IPV6_COMPRESS_REGEX.matcher(inputStr).matches();
        }
    }

    /**
     * 获取用户真实IP地址，不使用request.getRemoteAddr();的原因是有可能用户使用了代理软件方式避免真实IP地址,
     * <p>
     * 可是，如果通过了多级反向代理的话，X-Forwarded-For的值并不止一个，而是一串IP值，究竟哪个才是真正的用户端的真实IP呢？
     * 答案是取X-Forwarded-For中第一个非unknown的有效IP字符串。
     * <p>
     * 如：X-Forwarded-For：10.160.70.178,192.168.1.110, 192.168.1.120,
     * 192.168.1.130, 192.168.1.100
     * <p>
     * 用户真实IP为： 192.168.1.110
     *
     * @param request
     * @return
     */
    public static String getIpAddress(HttpServletRequest request) {

        Enumeration headerNames = request.getHeaderNames();
        //
        while (headerNames.hasMoreElements()) {
            String key = (String) headerNames.nextElement();
            String value = request.getHeader(key);
            logger.info("------nextElement ={} ,\n ------------request.getHeader(nextElement) ={}", key, value);
        }
        String ip = request.getHeader("x-forwarded-for");
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("x-real-ip");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_CLIENT_IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        // 返回多个ip 处理
        if (StringUtils.contains(ip, ",")) {
            logger.info("返回IP多条 ip ={}", ip);
            String[] addres = ip.split(",");
            for (int i = 0; i < addres.length; i++) {
                if (!addres[i].trim().startsWith("10.") && !addres[i].trim().startsWith("100.")
                        && !addres[i].trim().startsWith("192.") && !addres[i].trim().equals("127.0.0.1")) {
                    logger.info("过滤后只返回公网IP：{}", addres[i].trim());
                    ip = addres[i].trim();
                    break;
                }
            }
        }
        logger.info("-------getIpAddress----返回 ip ={}", ip);
        return ip;
    }

    /**
     * 获取二进制字节
     * @param hexStr
     * @return
     */
    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1) {
            return null;
        }
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

    public static void main(String args[]) {
        // String ipAddr = "A00:a00:100:f261::F15";
        // String ipAddr = "fe80:1295:8030:49ec:1fc6:57fa:0000:0000";
        // String ipAddr = "fe80:1295:8030:49ec:1fc6:57fa::";
        String ipAddr = "fe80::5c61:523f:74f1:1ce3%24";
        // String ipAddr = "192.168.1.50";//ipv4

        System.out.println("ip = " + ipAddr);
        if (isIPv6Address(ipAddr)) {
            System.out.println("----IPV6地址----");
            try {
                if (StringUtils.contains(ipAddr, "%")) {
                    ipAddr = ipAddr.substring(0, ipAddr.indexOf("%"));
                }
                InetAddress i = InetAddress.getByName(ipAddr);
                System.out.println("----IPv6?" + (i instanceof Inet6Address));
                ipAddr = i.getHostAddress();
                System.out.println(ipAddr);
                String[] ipv6arr = ipAddr.split(":");
                StringBuffer bf = new StringBuffer();
                for (String hex : ipv6arr) {
                    if (hex.equals("0")) {
                        hex = "0000";
                    } else {
                        int len = hex.length();
                        if (len == 1) {
                            hex = "000" + hex;
                        } else if (len == 2) {
                            hex = "00" + hex;
                        } else if (len == 3) {
                            hex = "0" + hex;
                        } else {
                            // 不需要补
                        }
                    }
                    byte[] t = parseHexStr2Byte(hex);
                    bf.append(BinaryCodec.toAsciiChars(t));
                }
                System.out.println(bf.length() );
                System.out.println(bf );
                System.out.println(bf.substring(20, 24));
            } catch (UnknownHostException e) {
                System.out.println("UnknownHostException="+ e);
            }
        } else if (isIPv4Address(ipAddr)) {
            System.out.println("IPV4地址");
        } else {
            System.out.println("不合法ip地址" + ipAddr);
        }
    }

}
