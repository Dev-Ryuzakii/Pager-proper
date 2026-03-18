import os
import subprocess
import random
import logging
import uuid

logger = logging.getLogger(__name__)

def generate_voice_decoy(source_path: str, output_path: str) -> bool:
    """
    Generate a 'scrambled' decoy using the sender's actual voice identity.
    Uses ffmpeg to slice, shuffle and pitch-shift segments of the source file.
    """
    if not os.path.exists(source_path):
        logger.error(f"Source voice identity not found: {source_path}")
        return False

    temp_prefix = f"temp_{uuid.uuid4().hex}"
    
    try:
        # 1. Get duration of source file
        cmd = [
            "ffprobe", "-v", "error", "-show_entries", "format=duration",
            "-of", "default=noprint_wrappers=1:nokey=1", source_path
        ]
        duration = float(subprocess.check_output(cmd).decode().strip())
        
        # 2. Slice into 4-6 random segments
        num_segments = random.randint(4, 6)
        segments = []
        seg_duration = duration / num_segments
        
        for i in range(num_segments):
            seg_file = f"{temp_prefix}_seg_{i}.m4a"
            start = i * seg_duration
            
            # Add some randomness to pitch and speed for 'AI-scramble' effect
            # tempo between 0.8 and 1.3, pitch between 0.8 and 1.3
            tempo = random.uniform(0.85, 1.25)
            # atempo filter changes speed without pitch
            # asetrate changes both (sounding like chipmunk/giant)
            
            # We'll use a mix of speed and pitch shift
            filter_chain = f"atempo={tempo}"
            if random.random() > 0.5:
                 # pitch up
                 filter_chain += f",asetrate=44100*1.2,atempo=0.83"
            
            cmd = [
                "ffmpeg", "-y", "-i", source_path,
                "-ss", str(start), "-t", str(seg_duration),
                "-filter:a", filter_chain,
                "-vn", seg_file
            ]
            subprocess.run(cmd, capture_output=True)
            if os.path.exists(seg_file):
                segments.append(seg_file)

        if not segments:
            return False

        # 3. Shuffle segments
        random.shuffle(segments)
        
        # 4. Concatenate segments
        concat_list = f"{temp_prefix}_list.txt"
        with open(concat_list, "w") as f:
            for s in segments:
                f.write(f"file '{os.path.abspath(s)}'\n")
        
        cmd = [
            "ffmpeg", "-y", "-f", "concat", "-safe", "0",
            "-i", concat_list, "-c", "copy", output_path
        ]
        subprocess.run(cmd, capture_output=True)
        
        # 5. Cleanup
        for s in segments:
            os.remove(s)
        os.remove(concat_list)
        
        return os.path.exists(output_path)

    except Exception as e:
        logger.error(f"Failed to generate voice decoy: {e}")
        # Clean up on error
        for i in range(10):
            p = f"{temp_prefix}_seg_{i}.m4a"
            if os.path.exists(p): os.remove(p)
        if os.path.exists(f"{temp_prefix}_list.txt"): os.remove(f"{temp_prefix}_list.txt")
        return False
