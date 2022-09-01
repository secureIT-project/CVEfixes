from __future__ import annotations

from dataclasses import dataclass, asdict, InitVar, field
from typing import Optional, Union


class MockUser:
    name: str = 'Default_user'

    def __init__(self, name: Optional[name]):
        if name:
            self.name = name


@dataclass(frozen=True, eq=True)
class MockMethod:
    UNIT_COMPLEXITY_LOW_RISK_THRESHOLD: int = 5
    UNIT_INTERFACING_LOW_RISK_THRESHOLD: int = 5
    UNIT_SIZE_LOW_RISK_THRESHOLD: int = 15
    complexity: int = 5
    end_line: int = 101
    fan_in: int = 0
    fan_out: int = 0
    filename: str = 'test.py'
    general_fan_out: int = 0
    length: int = 38
    long_name: str = 'b( )'
    name: str = 'b'
    nloc: int = 26
    parameters: list[str] = field(default_factory=lambda: [], compare=False)
    start_line: int = 64
    token_count: int = 235
    top_nesting_level: int = 0
    config: InitVar[dict] = None

    def __post_init__(self, config: dict):
        if config:
            self.__init__(**config)

    def method_row(self, before_change) -> dict[str, Union[str, int, list]]:
        return {
            'name': self.name,
            'signature': self.long_name,
            'parameters': self.parameters,
            'start_line': self.start_line,
            'end_line': self.end_line,
            'nloc': self.nloc,
            'complexity': self.complexity,
            'token_count': self.token_count,
            'top_nesting_level': self.top_nesting_level,
            'before_change': before_change,
        }


@dataclass
class MockModifiedFile:
    filename: str = 'test.py'
    old_path: str = 'Code/'
    new_path: str = 'Code/'
    change_type: str = 'modified'
    diff: str = 'some_diff'
    diff_parsed: dict[str, list[int]] = field(default_factory=lambda: {
        'added': [(3, 'a = floor(2+2)')], 'deleted': [(3, 'a = round(2+2)')]})
    added_lines: int = 1
    deleted_lines: int = 0
    source_code: str = """from math import floor
    def b():
        a = floor(2+2)
        print(a)"""
    source_code_before: str = """from math import floor
    def b()
        a = round(2+2)
        print(a)"""
    nloc: int = 100
    complexity: int = 100
    token_count: int = 100
    methods: list[MockMethod] = field(default_factory=lambda: [
        MockMethod(config={'start_line': 2, 'end_line': 4, 'length': 3}),
        MockMethod(config={'start_line': 59, 'end_line': 65, 'length': 7})])
    methods_before: list[MockMethod] = field(default_factory=lambda: [
        MockMethod(config={'start_line': 2, 'end_line': 4, 'length': 3}),
        MockMethod(config={'start_line': 59, 'end_line': 65, 'length': 7})])
    changed_methods: list[MockMethod] = field(default_factory=lambda: [
        MockMethod(config={'start_line': 2, 'end_line': 4, 'length': 3}),
    ])

    def file_row(self) -> dict['str', Union[int, str]]:
        return {
            'filename': self.filename,
            'old_path': self.old_path,
            'new_path': self.new_path,
            'change_type': self.change_type,  # i.e. added, deleted, modified or renamed
            'diff': self.diff,  # diff of the file as git presents it (e.g. @@xx.. @@)
            'diff_parsed': self.diff_parsed,  # diff parsed in a dict containing added and deleted lines lines
            'num_lines_added': self.added_lines,  # number of lines added
            'num_lines_deleted': self.deleted_lines,  # number of lines removed
            'code_after': self.source_code,
            'code_before': self.source_code_before,
            'nloc': self.nloc,
            'complexity': self.complexity,
            'token_count': self.token_count,
        }


@dataclass
class MockCommit:
    hash: str = 'test_commit_hash_abc123'
    author: MockUser = MockUser('test_author')
    author_date: str = 'some_date'
    author_timezone: int = 10000
    committer: MockUser = MockUser('test_committer')
    committer_date: str = 'some_date'
    committer_timezone: int = 10000
    msg: str = 'Added tests'
    merge: bool = False
    modified_files: list[MockModifiedFile] = field(default_factory=lambda: [MockModifiedFile()])
    parents: None = None
    insertions: int = 6
    deletions: int = 3
    dmm_unit_complexity: int = 10
    dmm_unit_interfacing: int = 10
    dmm_unit_size: int = 10

    def commit_row(self) -> dict['str', Union[str, int]]:
        tmp = asdict(self)
        tmp['author'] = self.author.name
        tmp['committer'] = self.committer.name
        tmp['num_lines_added'] = self.insertions
        tmp['num_lines_deleted'] = self.deletions

        del tmp['insertions']
        del tmp['deletions']

        return tmp


@dataclass
class MockRepo:
    def __init__(self, *args):
        self.mock_commits = [MockCommit()]

    def traverse_commits(self, *args):
        return self.mock_commits


@dataclass(frozen=True)
class MockGetRepo:
    full_name: str = field(default='test')
    description: str = field(default='test_desc')
    created_at: str = field(default='test_date')
    pushed_at: str = field(default='test_date')
    homepage: str = field(default='test_url')
    language: str = field(default='test_language')
    forks: str = field(default='test_int')
    stargazers_count: str = field(default='test_int')
    owner: str = field(default='test')

    def renamed(self) -> dict[str, str]:
        return {'repo_name': self.full_name, 'description': self.description, 'date_created': self.created_at,
                'date_last_push': self.pushed_at, 'homepage': self.homepage, 'repo_language': self.language,
                'forks_count': self.forks, 'stars_count': self.stargazers_count, 'owner': self.owner}


class MockGetUser:
    def __init__(self, *args):
        self.mocked_repo = MockGetRepo()

    def get_repo(self, *args):
        return self.mocked_repo
