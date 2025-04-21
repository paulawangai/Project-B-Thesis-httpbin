import re
import statistics

# Initialize lists to store values for each metric
loc, lloc, sloc, comments, multi, blank, single_comments = [], [], [], [], [], [], []

with open('metrics/final_metrics/raw_metrics_after.txt', 'r') as f:
    current_file = None
    for line in f:
        line = line.strip()

        if line and not line.startswith(' ') and ':' not in line:
            # This is a filename line
            current_file = line
        elif 'LOC:' in line:
            value = re.search(r'LOC: (\d+)', line)
            if value:
                loc.append(int(value.group(1)))
        elif 'LLOC:' in line:
            value = re.search(r'LLOC: (\d+)', line)
            if value:
                lloc.append(int(value.group(1)))
        elif 'SLOC:' in line:
            value = re.search(r'SLOC: (\d+)', line)
            if value:
                sloc.append(int(value.group(1)))
        elif 'Comments:' in line:
            value = re.search(r'Comments: (\d+)', line)
            if value:
                comments.append(int(value.group(1)))
        elif 'Multi:' in line:
            value = re.search(r'Multi: (\d+)', line)
            if value:
                multi.append(int(value.group(1)))
        elif 'Blank:' in line:
            value = re.search(r'Blank: (\d+)', line)
            if value:
                blank.append(int(value.group(1)))
        elif 'Single comments:' in line:
            value = re.search(r'Single comments: (\d+)', line)
            if value:
                single_comments.append(int(value.group(1)))

# Skip files with all zeros
non_zero_loc = [val for val in loc if val > 0]
non_zero_lloc = [val for val in lloc if val > 0]
non_zero_sloc = [val for val in sloc if val > 0]
non_zero_comments = [val for val in comments if val > 0]
non_zero_multi = [val for val in multi if val > 0]
non_zero_blank = [val for val in blank if val > 0]
non_zero_single_comments = [val for val in single_comments if val > 0]

# Calculate averages (excluding zero values)
print(f"Average LOC: {statistics.mean(non_zero_loc) if non_zero_loc else 'N/A'}")
print(f"Average LLOC: {statistics.mean(non_zero_lloc) if non_zero_lloc else 'N/A'}")
print(f"Average SLOC: {statistics.mean(non_zero_sloc) if non_zero_sloc else 'N/A'}")
print(f"Average Comments: {statistics.mean(non_zero_comments) if non_zero_comments else 'N/A'}")
print(f"Average Multi: {statistics.mean(non_zero_multi) if non_zero_multi else 'N/A'}")
print(f"Average Blank: {statistics.mean(non_zero_blank) if non_zero_blank else 'N/A'}")
print(f"Average Single comments: {statistics.mean(non_zero_single_comments) if non_zero_single_comments else 'N/A'}")

# Calculate comment density (Comments / SLOC)
if non_zero_sloc and non_zero_comments:
    non_zero_files = []
    for i in range(min(len(sloc), len(comments))):
        if sloc[i] > 0:
            non_zero_files.append((comments[i], sloc[i]))

    comment_density = [c / s for c, s in non_zero_files]
    print(f"Average Comment Density: {statistics.mean(comment_density)}")
else:
    print("Average Comment Density: N/A")

# Calculate total averages
total_files = len(loc)
files_with_code = len(non_zero_loc)
print(f"Total Files Analyzed: {total_files}")
print(f"Files With Code: {files_with_code}")
print(f"Total LOC: {sum(loc)}")
print(f"Total LLOC: {sum(lloc)}")
print(f"Total SLOC: {sum(sloc)}")
print(f"Total Comments: {sum(comments)}")
print(f"Total Blank Lines: {sum(blank)}")