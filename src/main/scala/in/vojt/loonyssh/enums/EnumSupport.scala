package in.vojt.loonyshh.enums

import scala.deriving._
import scala.compiletime._

case object Product0 extends Product

trait EnumSupport[E<:Enum]:
    def fromName:Map[String, E]
    def fromParam:Map[String, E] = ???

object EnumSupport:
    inline given values[E<:Enum](using m: Mirror.SumOf[E]) as EnumSupport[E] = new EnumSupport:
        override val fromName = enumerate[E, m.MirroredElemTypes, m.MirroredElemLabels](0)

    /** Currently it would fail on enums which have cases with params. */
    inline private def enumerate[E<:Enum,T,L](i:Int):Map[String, E] = inline erasedValue[(T,L)] match
        case _: (Unit, Unit) => Map.empty
        case _: (t *: ts, l *: ls) => 
            val key = constValue[l].asInstanceOf[String]
            val value = summonInline[Mirror.ProductOf[t]].fromProduct(Product0).asInstanceOf[E]

            enumerate[E,ts,ls](i+1) + (key -> value)