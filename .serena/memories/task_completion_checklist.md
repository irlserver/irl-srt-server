# Task Completion Checklist

When completing a development task:

1. **Code Changes**
   - Ensure code follows the project naming conventions
   - Add appropriate logging using spdlog
   - Handle errors appropriately with return codes
   - Clean up any allocated resources

2. **Build**
   - Rebuild the project: `cd build && make -j`
   - Fix any compilation errors
   - Fix any warnings if possible

3. **Testing**
   - Test the functionality manually if applicable
   - Check logs for errors
   - Verify expected behavior

4. **Documentation**
   - Update relevant documentation if needed
   - Add comments for complex logic
   - Update configuration examples if config changes

No automated testing framework is currently in the project.
No linting/formatting tools are configured.
