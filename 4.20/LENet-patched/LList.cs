using System;

namespace LENet
{
    public sealed class LList<T> where T : LList<T>.Element
    {
        public abstract class Element
        {
            public readonly Node Node;
            public Element()
            {
                Node = new Node(this as T);
            }
        }

        public sealed class Node
        {
            public Node Next { get; private set; }

            public Node Prev { get; private set; }

            public readonly T Value;

            public Node()
            {
                Next = this;
                Prev = this;
                Value = default;
            }

            public Node(T v)
            {
                Next = this;
                Prev = this;
                Value = v;
            }

            // Inserts node before this node
            public Node Insert(Node what)
            {
                var where = this;

                what.Prev = Prev;
                what.Next = where;

                where.Prev.Next = what;
                where.Prev = what;

                return what;
            }

            // Removes this node
            public Node Remove()
            {
                var what = this;

                what.Prev.Next = Next;
                what.Next.Prev = Prev;

                return what;
            }

            // Inserts range of nodes before this node
            public Node Move(Node first, Node last)
            {
                var where = this;

                first.Prev.Next = last.Next;
                last.Next.Prev = first.Prev;

                first.Prev = Prev;
                last.Next = where;

                first.Prev.Next = first;
                where.Prev = last;

                return first;
            }

            public void Clear()
            {
                Next = this;
                Prev = this;
            }
        }

        private readonly Node _root = new Node();

        public bool Empty => Begin == End;

        public Node Begin => _root.Next;

        public Node End => _root;

        public void Clear()
        {
            _root.Clear();
        }
    }
}
