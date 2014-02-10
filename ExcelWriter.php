<?php
/**
 * Created by Cyril Lee.
 * Date: 2013/4/20
 * Time: 下午 12:13
 */
class ExcelWriter
{
    private $groupName;

    private $fromTime;
    private $toTime;
    private $fansOrderArray;

    public function ExcelWriter($groupName, $fromTime, $toTime, $fansOrderArray){
        $this -> groupName = $groupName;
        $this -> fromTime = $fromTime;
        $this -> toTime = $toTime;
        //$this -> fansOrderArray = array();
        $this -> fansOrderArray = $fansOrderArray;
        $this -> config();
    }

    private function config(){
        if(!is_dir('excel-report')){
            mkdir('excel-report',0755,true);
        }
    }

    public function writeToFile(){
        $objPHPExcel = new PHPExcel();
        $objPHPExcel->setActiveSheetIndex(0);

        // set the cell width to follow the content in the excel report.
        $objPHPExcel->getActiveSheet()->getColumnDimension('A')->setAutoSize(true);
        $objPHPExcel->getActiveSheet()->getColumnDimension('B')->setAutoSize(true);
        $objPHPExcel->getActiveSheet()->getColumnDimension('C')->setAutoSize(true);
        $objPHPExcel->getActiveSheet()->getColumnDimension('D')->setAutoSize(true);
        $objPHPExcel->getActiveSheet()->getColumnDimension('E')->setAutoSize(true);

        $objPHPExcel->getActiveSheet()->setCellValue('A1', "粉絲團名稱");
        $objPHPExcel->getActiveSheet()->setCellValue('B1', "開始時間");
        $objPHPExcel->getActiveSheet()->setCellValue('C1', "結束時間");
        $objPHPExcel->getActiveSheet()->setCellValue('D1', "粉絲名稱");
        $objPHPExcel->getActiveSheet()->setCellValue('E1', "分數");

        $objPHPExcel->getActiveSheet()->setCellValue('A2', $this -> groupName);
        $objPHPExcel->getActiveSheet()->setCellValue('B2', $this -> fromTime);
        $objPHPExcel->getActiveSheet()->setCellValue('C2', $this -> toTime);
        $i=0;
        foreach ($this->fansOrderArray as $fansID => $fansInfo) {
            $i++;
            $objPHPExcel->getActiveSheet()->setCellValue('D' . (1 + $i), $fansInfo['name']);
            $objPHPExcel->getActiveSheet()->setCellValue('E' . (1 + $i), $fansInfo['score']);
        }

        $objPHPExcel->getActiveSheet()->getProtection()->setSheet(true);

        $objWriter = new PHPExcel_Writer_Excel2007($objPHPExcel);
        $objWriter->save("excel-report/fansAnalysis.xlsx");

        $objWriter = new PHPExcel_Writer_Excel5($objPHPExcel);
        $objWriter->save("excel-report/fansAnalysis.xls");

    }

}
