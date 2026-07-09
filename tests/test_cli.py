from main import build_parser


def test_cli_allows_default_watch_mode():
    args = build_parser().parse_args([])

    assert args.command is None
