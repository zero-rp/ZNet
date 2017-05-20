project(lua)
aux_source_directory(./src src)
add_library(lua STATIC ${src})
set_target_properties(lua PROPERTIES output_name "lua")
