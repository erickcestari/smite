// Methods EclairInstrumenterTest instruments and runs.
public class InstrumenterFixture {

  // a=false takes the arc from the if straight to the return, which the
  // a=true path also reaches: a critical edge.
  public static int skip(boolean a) {
    int x = 0;
    if (a) {
      x = 1;
    }
    return x;
  }

  // Case 2 is entered from the switch and by falling through from case 1, so
  // the switch's arc into it is critical.
  public static int fallThrough(int k) {
    int r = 0;
    switch (k) {
      case 1:
        r = 10;
      case 2:
        r += 1;
        break;
      default:
        r = -1;
    }
    return r;
  }

  // Each branch's target has a single entry, so nothing is critical.
  public static int either(boolean a) {
    return a ? 1 : 2;
  }
}
