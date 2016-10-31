project('clevis', 'c')

cc = meson.get_compiler('c')
add_global_arguments(
  '-Wall',
  '-Wextra',
  '-Werror',
  '-Wstrict-aliasing',
  '-Wchar-subscripts',
  '-Wformat-security',
  '-Wmissing-declarations',
  '-Wmissing-prototypes',
  '-Wnested-externs',
  '-Wpointer-arith',
  '-Wshadow',
  '-Wsign-compare',
  '-Wstrict-prototypes',
  '-Wtype-limits',
  '-Wno-missing-field-initializers',
  '-Wno-unused-parameter',
  language: 'c'
)

luksmeta = dependency('luksmeta', version: '>=3')
jose = dependency('jose-openssl', version: '>=6')
http_parser = cc.find_library('http_parser')
libcrypto = dependency('libcrypto')
udisks2 = dependency('udisks2')
dracut = dependency('dracut')

if meson.version().version_compare('>=0.36.0')
  dracutmod = '/'.join([dracut.get_pkgconfig_variable('dracutmodulesdir'), '60clevis'])
else
  dracutmod = 'lib/dracut/modules.d/60clevis'
endif

http = static_library('http', ['http.c', 'http.h'], dependencies: http_parser)
ra = static_library('readall', ['readall.c', 'readall.h'])

executable(
  'clevis',
  'clevis.c',
  install: true
)

executable(
  'clevis-encrypt',
  'clevis-encrypt.c',
  install: true
)

executable(
  'clevis-decrypt',
  'clevis-decrypt.c',
  install: true,
  dependencies: jose
)

executable(
  'clevis-pin-sss',
  ['clevis-pin-sss.c', 'sss.c', 'sss.h'],
  link_with: ra,
  install: true,
  dependencies: [jose, libcrypto]
)

executable(
  'clevis-pin-http',
  ['clevis-pin-http.c'],
  link_with: [ra, http],
  install: true,
  dependencies: jose
)

executable(
  'clevis-pin-tang',
  ['clevis-pin-tang.c', 'tang.c', 'tang.h'],
  link_with: [ra, http],
  install: true,
  dependencies: [jose, libcrypto]
)

executable(
  'clevis-pin-test',
  'clevis-pin-test.c',
  link_with: ra,
  dependencies: jose
)

cfg = configuration_data()
cfg.set('libexecdir', '/'.join([get_option('prefix'), get_option('libexecdir')]))

configure_file(
  input: 'clevis-luks-udisks2.desktop.in',
  output: 'clevis-luks-udisks2.desktop',
  configuration: cfg,
  install_dir: get_option('sysconfdir') + '/xdg/autostart'
)

executable(
  'clevis-luks-udisks2', 'clevis-luks-udisks2.c',
  install_dir: get_option('libexecdir'),
  dependencies: [ luksmeta, udisks2 ],
  install: true
)

executable(
  'test-pin-httpd', 'test-pin-httpd.c',
  dependencies: [ http_parser ]
)

install_data('clevis-bind-luks', install_dir: get_option('bindir'))
install_data('dracut/module-setup.sh', 'dracut/clevis-hook.sh', install_dir: dracutmod)

test('clevis-pin-test', find_program('test-pin-test'))
test('clevis-pin-http', find_program('test-pin-http'))
test('clevis-pin-sss',  find_program('test-pin-sss'))
test('clevis-pin-tang', find_program('test-pin-tang'))
