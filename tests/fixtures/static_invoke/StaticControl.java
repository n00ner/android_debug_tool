/** Desktop JVM control for issue #23 static-invoke reproduction.
 *  Run: javac -g StaticControl.java
 *       java -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=7777 StaticControl
 *  The main thread parks in busyLoop() so the debugger can break there,
 *  then ClassType.InvokeMethod(StaticControl.answer) is driven over JDWP.
 */
public class StaticControl {
    public static int answer(String s) {
        return Integer.parseInt(s) + 1;
    }

    static volatile boolean stop = false;

    public static void busyLoop() {
        int i = 0;                       // breakpoint target line
        while (!stop) {
            i++;
            if (i == Integer.MAX_VALUE) i = 0;
        }
    }

    public static void main(String[] args) {
        busyLoop();
    }
}
