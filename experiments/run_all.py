"""Compatibility alias for the canonical research command dispatcher.

New instructions should use ``experiments/run_research.py``. This alias is
kept only so old local commands cannot invoke the retired AgentDojo workflow.
"""

from run_research import main


if __name__ == "__main__":
    main()
