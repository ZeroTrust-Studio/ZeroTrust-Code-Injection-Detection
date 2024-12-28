---@author ZeroTrust
local LoadResourceFile <const> = LoadResourceFile
local GetResourceByFindIndex <const> = GetResourceByFindIndex
local GetNumResources <const> = GetNumResources
local GetResourcePath <const> = GetResourcePath

local DEBUG <const> = false

---@param resource string
---@param pattern string
local function getFilesFromPattern(resource, pattern)
    local files = {}
    local baseDir = pattern:match("(.*/)")
    local searchPattern = pattern:match(".*/(.*%.lua)")
    local fullPath

    if baseDir and searchPattern then
        local resourcePath = GetResourcePath(resource)
        fullPath = resourcePath .. "/" .. baseDir
        local command = 'dir "' .. fullPath .. '" /b /a-d'
        local p = io.popen(command)
        if DEBUG then print("^2Searching path^7: "..fullPath) end
        if p then
            for file in p:lines() do
                table.insert(files, baseDir .. file)
            end
            p:close()
        end
    end

    return files, fullPath
end

---@param content string
local function checkMultiLinePattern(content)
    -- Split content into lines
    local lines = {}
    for line in content:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end
    
    -- Check for PerformHttpRequest followed by assert(load) within 5 lines
    for i = 1, #lines do
        if lines[i]:find("PerformHttpRequest") then
            for j = i, math.min(i + 5, #lines) do
                if lines[j]:find("assert%s*%(s*load%s*%(") then
                    return true
                end
            end
        end
    end
    return false
end

CreateThread(function()
    local AnalyzeCount, FoundVulnerability = 1, 0
    for i = 0, GetNumResources() - 1 do
        local resource = GetResourceByFindIndex(i)
        local manifest = LoadResourceFile(resource, "__resource.lua") or LoadResourceFile(resource, "fxmanifest.lua")
        if manifest then
            local files = {}
            local filePath = GetResourcePath(resource)
            
            -- Handles format: server_scripts { "file1.lua", "file2.lua" } & server_scripts { "*.lua" }
            for script in manifest:gmatch('[cs]erver_script[s]?%s*{(.-)}') do
                for file in script:gmatch('"([^"]+%.lua)"') do
                    if file:find("%*") then
                        local matchedFiles, path = getFilesFromPattern(resource, file)
                        filePath = path
                        for _, matchedFile in ipairs(matchedFiles) do
                            if not files[matchedFile] then
                                AnalyzeCount += 1
                                files[matchedFile] = true
                            end
                        end
                    else
                        if not files[file] then
                            AnalyzeCount += 1
                            files[file] = true
                        end
                    end
                end
            end

            -- Handles format: server_script "file.lua" & server_script "*.lua"
            for script in manifest:gmatch('[cs]erver_script[s]?%s*"([^"]+%.lua)"') do
                if script:find("%*") then
                    local matchedFiles, path = getFilesFromPattern(resource, script)
                    filePath = path
                    for _, matchedFile in ipairs(matchedFiles) do
                        if not files[matchedFile] then
                            AnalyzeCount += 1
                            files[matchedFile] = true
                        end
                    end
                else
                    if not files[script] then
                        AnalyzeCount += 1
                        files[script] = true
                    end
                end
            end

            for fileName in pairs(files) do
                local fileContent = LoadResourceFile(resource, fileName)
                if fileContent then
                    if DEBUG then print("^2Analyzing^7: "..resource.."/"..fileName) end
                    local hasPattern = checkMultiLinePattern(fileContent)
                    if hasPattern then
                        FoundVulnerability += 1
                        print("^3ZeroTrust External Code Injection Detected^7\n\nResource: ^1"..resource.."^7, in file ^1"..fileName.."^7 contains suspicious pattern (PerformHttpRequest with assert/load)")
                        if filePath then
                            print("Path: ^1".. filePath .."^7\n")
                        end
                    end
                end
            end
        end
    end
    print("^2ZeroTrust Scan Completed^7 Analyzed "..AnalyzeCount.." files. " .. ((FoundVulnerability > 0) and "\n^1x"..FoundVulnerability.." Vulnerability Detected^7" or "No vulnerability detected"))
end)