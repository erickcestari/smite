import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import sun.misc.Unsafe;

class EclairInstrumenterTest {

  // The fixture's probe IDs start at 0 and stay below this.
  static final int MAX_PROBES = 1000;

  @Test
  void ifElseGetsOneProbePerBlock() throws Exception {
    // Entry, the fall-through after the jump, the else label and the label
    // where both branches meet. No arc is critical, so nothing is split.
    assertEquals(4, probesIn("either"));
  }

  @Test
  void criticalEdgeFromJumpHasItsOwnProbe() throws Exception {
    Method skip = fixture().getMethod("skip", boolean.class);
    Set<Integer> taken = probesFiredBy(() -> skip.invoke(null, true));
    Set<Integer> skipped = probesFiredBy(() -> skip.invoke(null, false));
    assertFalse(taken.containsAll(skipped));
  }

  @Test
  void criticalEdgeFromSwitchHasItsOwnProbe() throws Exception {
    Method fallThrough = fixture().getMethod("fallThrough", int.class);
    Set<Integer> viaCase1 = probesFiredBy(() -> fallThrough.invoke(null, 1));
    Set<Integer> direct = probesFiredBy(() -> fallThrough.invoke(null, 2));
    assertFalse(viaCase1.containsAll(direct));
  }

  static byte[] instrumentedFixture() throws Exception {
    try (InputStream in = EclairInstrumenterTest.class.getResourceAsStream(
             "/InstrumenterFixture.class")) {
      int[] nextId = {0};
      byte[] bytecode = EclairInstrumenter.instrument(in.readAllBytes(), nextId);
      assertTrue(nextId[0] <= MAX_PROBES);
      return bytecode;
    }
  }

  // Defines the instrumented fixture in its own loader, so its probes call the
  // same EclairSanCov this test reads.
  static Class<?> fixture() throws Exception {
    byte[] bytecode = instrumentedFixture();
    return new ClassLoader(EclairInstrumenterTest.class.getClassLoader()) {
      Class<?> define() {
        return defineClass("InstrumenterFixture", bytecode, 0, bytecode.length);
      }
    }.define();
  }

  static int probesIn(String methodName) throws Exception {
    ClassNode node = new ClassNode();
    new ClassReader(instrumentedFixture()).accept(node, 0);
    int probes = 0;
    for (MethodNode method : node.methods) {
      if (!method.name.equals(methodName)) {
        continue;
      }
      for (AbstractInsnNode insn : method.instructions) {
        if (insn instanceof MethodInsnNode call &&
            call.owner.equals("EclairSanCov")) {
          probes++;
        }
      }
    }
    return probes;
  }

  interface Call {
    void run() throws Exception;
  }

  // IDs of the probes whose counters changed while `call` ran.
  static Set<Integer> probesFiredBy(Call call) throws Exception {
    long map = mapAddress();
    byte[] before = new byte[MAX_PROBES];
    for (int id = 0; id < MAX_PROBES; id++) {
      before[id] = UNSAFE.getByte(map + id);
    }
    call.run();
    Set<Integer> fired = new HashSet<>();
    for (int id = 0; id < MAX_PROBES; id++) {
      if (UNSAFE.getByte(map + id) != before[id]) {
        fired.add(id);
      }
    }
    return fired;
  }

  static long mapAddress() throws Exception {
    Field field = EclairSanCov.class.getDeclaredField("MAP_ADDR");
    field.setAccessible(true);
    return field.getLong(null);
  }

  static final Unsafe UNSAFE;
  static {
    try {
      Field field = Unsafe.class.getDeclaredField("theUnsafe");
      field.setAccessible(true);
      UNSAFE = (Unsafe)field.get(null);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }
}
