// commitlint configuration for the SiberIndo CTI/DRP monorepo.
//
// Enforces Conventional Commits (https://www.conventionalcommits.org/) so that
// release-please can derive the version + CHANGELOG and the `pr-title-lint` CI
// check stays consistent with local hooks.
//
// See docs/engineering/conventional-commits.md for the full convention, and for
// wiring this into a local husky `commit-msg` hook:
//   npx --no -- commitlint --edit "$1"
//
// Requires devDependencies (install once if you want local linting):
//   npm i -D @commitlint/cli @commitlint/config-conventional husky

module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    // Allowed commit types (matches the table in conventional-commits.md).
    'type-enum': [
      2,
      'always',
      [
        'feat',
        'fix',
        'docs',
        'chore',
        'refactor',
        'perf',
        'test',
        'build',
        'ci',
        'revert',
      ],
    ],

    // Scopes are the service/module touched. Listed for guidance; kept at
    // warning level (1) and not "always" required, so cross-cutting or
    // repo-wide changes may omit a scope without failing the lint.
    'scope-enum': [
      1,
      'always',
      [
        // services
        'auth',
        'user',
        'asset',
        'alert-engine',
        'dlm',
        'clm',
        'dwm',
        'brm',
        'phm',
        'investigation',
        'notification',
        'audit',
        'indicator',
        'takedown',
        // frontend
        'web',
        'admin',
        'mobile',
        // shared packages
        'shared-types',
        'utils',
        // cross-cutting
        'infra',
        'api',
        'db',
        'ci',
        'docs',
        'deps',
        'engineering',
      ],
    ],

    // Subject style: imperative, lowercase, no trailing period, kept short.
    'subject-case': [2, 'never', ['sentence-case', 'start-case', 'pascal-case', 'upper-case']],
    'subject-full-stop': [2, 'never', '.'],
    'header-max-length': [2, 'always', 100],
  },
};
