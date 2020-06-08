package in.vojt.diff

import scala.deriving._
import scala.compiletime._

type Difference = Map[List[String], String]

trait Diff[T]:
    def diff(u:T, v:T):Difference

object Diff:
    given[S<:Singleton] as Diff[S]:
        def diff(u:S, v:S):Difference =
            if(u == v) Map.empty
            else Map(Nil -> s"$u != $v")

    inline given seq[P](using dp:Diff[P]) as Diff[Seq[P]] = new Diff:
        def diff(u:Seq[P], v:Seq[P]): Difference = 
            // yay! should be ...
            if(u == v) Map.empty
            else Map(Nil -> s"$u != $v")

    inline given sum[P](using m: Mirror.SumOf[P]) as Diff[P] = new Diff:
        def diff(u:P, v:P): Difference = 
            // yay! this is dumb, assumes that there are only parameterless cases
            if(u == v) Map.empty
            else Map(Nil -> s"$u != $v")

    inline given prodcut[P](using m: Mirror.ProductOf[P]) as Diff[P] = new Diff:
        def diff(u:P, v:P): Difference = diffProduct[P,m.MirroredElemTypes,m.MirroredElemLabels](u,v)(0)

    private inline def diffProduct[P,T,L](u:P,v:P)(i:Int):Difference =
        inline erasedValue[(T,L)] match
            case _: (t *: ts, l *: ls) =>
                val key = constValue[l].asInstanceOf[String]
                val dt = summonInline[Diff[t]]

                val ui = productElement(u,i).asInstanceOf[t]
                val vi = productElement(v,i).asInstanceOf[t]

                val diffs = dt.diff(ui,vi).map((k,v) => (key::k,v))
                diffProduct[P,ts,ls](u,v)(i+1) ++ diffs
            case _: (Unit, Unit) =>
                Map.empty
