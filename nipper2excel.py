import lxml.etree as ET
import csv
import sys

def extract_text(element):
    """Return the concatenated and stripped text content from an element."""
    return "".join(element.itertext()).strip()

def parse_nipper_xml(xml_file, csv_file):
    # Create an XML parser with recover enabled to handle minor malformations
    parser = ET.XMLParser(recover=True)
    try:
        tree = ET.parse(xml_file, parser)
    except ET.XMLSyntaxError as e:
        print(f"XML Parse Error: {e}")
        sys.exit(1)
    root = tree.getroot()

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # Define CSV header
        writer.writerow([
            "Section Index",
            "Section Title",
            "Reference",
            "Description",
            "Rationale",
            "Remediation",
            "Steps",
            "Affected Device",
            "Result",
            "Impact"
        ])

        # Iterate over every section (including nested ones)
        for section in root.iter("section"):
            sec_index = section.get("index", "")
            sec_title = section.get("title", "")
            sec_ref = section.get("ref", "")

            # Initialize fields for section-level text content
            description = ""
            rationale = ""
            remediation = ""
            steps = []
            additional_text = []  # To capture any extra text blocks

            # Process direct child elements of the section
            for child in section:
                tag = child.tag.lower()
                if tag == "text":
                    ttitle = child.get("title", "").strip().lower()
                    text_content = extract_text(child)
                    if ttitle == "description":
                        description = text_content
                    elif ttitle == "rationale":
                        rationale = text_content
                    elif ttitle == "remediation":
                        remediation = text_content
                    else:
                        additional_text.append(text_content)
                elif tag == "list":
                    # Process list items as steps
                    for li in child.findall("listitem"):
                        step_text = extract_text(li)
                        if step_text:
                            steps.append(step_text)

            if additional_text:
                steps.append(" ".join(additional_text))

            # Check for a device results table
            table = section.find("table")
            if table is not None:
                tablebody = table.find("tablebody")
                if tablebody is not None:
                    for row in tablebody.findall("tablerow"):
                        cells = row.findall("tablecell")
                        if len(cells) >= 2:
                            device = extract_text(cells[0])
                            result = extract_text(cells[1])
                            # Write one CSV row per device row
                            writer.writerow([
                                sec_index,
                                sec_title,
                                sec_ref,
                                description,
                                rationale,
                                remediation,
                                "\n".join(steps),
                                device,
                                result,
                                ""  # Impact (if applicable)
                            ])
            else:
                # If no table is present, output a row with blank device details.
                writer.writerow([
                    sec_index,
                    sec_title,
                    sec_ref,
                    description,
                    rationale,
                    remediation,
                    "\n".join(steps),
                    "",
                    "",
                    ""
                ])

    print(f"CSV export completed: {csv_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python nipper_xml_to_csv.py <input_xml_file> <output_csv_file>")
    else:
        parse_nipper_xml(sys.argv[1], sys.argv[2])
