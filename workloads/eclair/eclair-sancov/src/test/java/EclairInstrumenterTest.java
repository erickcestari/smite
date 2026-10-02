import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.InputStream;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

class EclairInstrumenterTest {

  @Test
  void ifElseGetsOneProbePerBlock() throws Exception {
    // Entry, the fall-through after the jump, the else label and the label
    // where both branches meet.
    assertEquals(4, probesIn("either"));
  }

  static byte[] instrumentedFixture() throws Exception {
    try (InputStream in = EclairInstrumenterTest.class.getResourceAsStream(
             "/InstrumenterFixture.class")) {
      return EclairInstrumenter.instrument(in.readAllBytes(), new int[] {0});
    }
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
}
