package in.vojt.loonyshh.enums

import scala.deriving._
import scala.compiletime._

case object Product0

trait EnumSupport[E<:Enum]:
    def fromName:Map[String, E]
    def byName(name:String, params:Product):Option[E]

object EnumSupport:
    inline given values[E<:Enum](using m: Mirror.SumOf[E]) as EnumSupport[E] = new EnumSupport:
        override val fromName =
            _fromName[E, m.MirroredElemTypes, m.MirroredElemLabels](0)
        override def byName(name:String, params:Product):Option[E] =
            _byName[E, m.MirroredElemTypes, m.MirroredElemLabels](name, params)

    /** Currently it would fail on enums which have cases with params. */
    inline private def _fromName[E<:Enum,T,L](i:Int):Map[String, E] = inline erasedValue[(T,L)] match
        case _: (Unit, Unit) => Map.empty
        case _: (t *: ts, l *: ls) =>
            val key = constValue[l].asInstanceOf[String]
            val mirror = summonInline[Mirror.ProductOf[t]]

            try
                val value = mirror.fromProduct(Product0).asInstanceOf[E]
                _fromName[E,ts,ls](i+1) + (key -> value)
            catch
                // ignoring parametric types... Tuple.Size[mirror.MirrorElemLabels] does not work since the type info gets los
                case e:java.lang.IndexOutOfBoundsException => _fromName[E,ts,ls](i+1)



    inline def _byName[E<:Enum,T,L](name:String, params:Product):Option[E] = inline erasedValue[(T,L)] match
        case _: (t *: ts, l *: ls) =>
            if constValue[l] == name then
                Some(summonInline[Mirror.ProductOf[t]].fromProduct(params).asInstanceOf[E])
            else
                _byName[E,ts,ls](name, params)
        case _: (Unit, Unit) =>
            None
