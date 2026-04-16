namespace LENet;

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
		public readonly T Value;

		public Node Next { get; private set; }

		public Node Prev { get; private set; }

		public Node()
		{
			Next = this;
			Prev = this;
			Value = null;
		}

		public Node(T v)
		{
			Next = this;
			Prev = this;
			Value = v;
		}

		public Node Insert(Node what)
		{
			what.Prev = Prev;
			what.Next = this;
			Prev.Next = what;
			Prev = what;
			return what;
		}

		public Node Remove()
		{
			Prev.Next = Next;
			Next.Prev = Prev;
			return this;
		}

		public Node Move(Node first, Node last)
		{
			first.Prev.Next = last.Next;
			last.Next.Prev = first.Prev;
			first.Prev = Prev;
			last.Next = this;
			first.Prev.Next = first;
			Prev = last;
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
