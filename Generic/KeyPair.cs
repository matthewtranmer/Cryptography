using System.Numerics;

namespace Cryptography.Generic
{
    public class KeyPair
    {
        public BigInteger private_component { get; }
        public Coordinate public_component { get; }
        public string public_component_string { get; }

        private ECPoint curve_point;

        public KeyPair(Curves curve)
        {
            curve_point = new ECPoint(curve);
            private_component = ECC.randomBigInteger(1, curve_point.getOrder() - 1);

            curve_point.multiply(private_component);
            public_component = curve_point.getCoords();
            public_component_string = ECC.coordinateToString(public_component);
        }

        public KeyPair(Curves curve, BigInteger private_component)
        {
            this.private_component = private_component;
            curve_point = new ECPoint(curve);

            curve_point.multiply(private_component);
            public_component=curve_point.getCoords();
            public_component_string= ECC.coordinateToString(public_component);
        }
    }
}
