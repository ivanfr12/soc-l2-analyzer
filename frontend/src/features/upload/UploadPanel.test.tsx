import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import UploadPanel from "./UploadPanel";

describe("UploadPanel", () => {
  it("accepts an XLSX selection but waits for an explicit submit", () => {
    const onAnalyze = vi.fn().mockResolvedValue(undefined);
    const onFileSelected = vi.fn();
    render(
      <UploadPanel
        isProcessing={false}
        error={null}
        onAnalyze={onAnalyze}
        onFileSelected={onFileSelected}
        onClearError={vi.fn()}
      />,
    );

    const file = new File(["workbook"], "events.xlsx", {
      type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    });
    fireEvent.change(screen.getByLabelText("Seleccionar archivo Excel XLSX"), {
      target: { files: [file] },
    });

    expect(screen.getByText("events.xlsx")).toBeInTheDocument();
    expect(onFileSelected).toHaveBeenLastCalledWith(file);
    expect(onAnalyze).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Analizar workbook" }));
    expect(onAnalyze).toHaveBeenCalledWith(file);
  });

  it("rejects unsupported extensions before submission", () => {
    const onAnalyze = vi.fn();
    render(
      <UploadPanel
        isProcessing={false}
        error={null}
        onAnalyze={onAnalyze}
        onFileSelected={vi.fn()}
        onClearError={vi.fn()}
      />,
    );

    fireEvent.change(screen.getByLabelText("Seleccionar archivo Excel XLSX"), {
      target: { files: [new File(["data"], "events.csv")] },
    });

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Seleccioná un archivo .xlsx",
    );
    expect(screen.getByRole("button", { name: "Analizar workbook" })).toBeDisabled();
    expect(onAnalyze).not.toHaveBeenCalled();
  });

  it("rejects files larger than the configured API limit", () => {
    render(
      <UploadPanel
        maxBytes={1024}
        isProcessing={false}
        error={null}
        onAnalyze={vi.fn()}
        onFileSelected={vi.fn()}
        onClearError={vi.fn()}
      />,
    );

    fireEvent.change(screen.getByLabelText("Seleccionar archivo Excel XLSX"), {
      target: {
        files: [
          new File(["x".repeat(1025)], "events.xlsx", {
            type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
          }),
        ],
      },
    });

    expect(screen.getByRole("alert")).toHaveTextContent(
      "supera el límite de 1 KiB",
    );
    expect(screen.getByRole("button", { name: "Analizar workbook" })).toBeDisabled();
  });
});
